//! Decoys: files no program has a reason to open, and addresses no program has a reason to
//! connect to. Hand-placed files are listed in dnom.yaml (`decoys.paths`); generated ones
//! (`decoys.auto`) are planted by `dnom classify` in the user's home when it starts and
//! removed when it stops. Decoy addresses (`decoys.addresses`) are only a list: nothing
//! listens there and dnom never connects; an attempt to reach one is the signal.
//!
//! Generated decoys:
//! - Names are picked at random from pools of believable names that the real tools (ssh, the
//!   AWS CLI) never load on their own. Contents have the right shape and are random: nothing
//!   here can log in anywhere.
//! - dnom never overwrites a file, and removes only files it created that are unchanged.
//! - The set is remembered in `<state dir>/decoys.json`, so a later start can remove what a
//!   run that was killed left behind. That file is a tripwire like dnom.yaml: another program
//!   reading it is reported.
//! - Only for a live run on this machine: never when replaying a recording or reading
//!   another machine's events.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    net::{IpAddr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DecoyConfig {
    /// Hand-placed decoys: an absolute path, or a directory (ending in `/`) for everything
    /// under it.
    pub paths: Vec<String>,
    /// Decoy addresses: `IP` (any port) or `IP:PORT` (`[v6]:PORT`).
    pub addresses: Vec<String>,
    /// Kinds of decoys dnom generates itself.
    pub auto: Auto,
    /// While dnom runs, replace the generated set after this many days (0: one set per run).
    pub rotate_days: u64,
}

impl Default for DecoyConfig {
    fn default() -> Self {
        Self { paths: Vec::new(), addresses: Vec::new(), auto: Auto::default(), rotate_days: 7 }
    }
}

impl DecoyConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        Addresses::parse(&self.addresses).map(|_| ())
    }
}

/// The decoy addresses of dnom.yaml, ready to match connection attempts against.
#[derive(Default)]
pub struct Addresses(Vec<(IpAddr, Option<u16>)>);

impl Addresses {
    pub fn parse(entries: &[String]) -> anyhow::Result<Self> {
        let mut list = Vec::new();
        for entry in entries {
            let parsed = match (entry.parse::<SocketAddr>(), entry.parse::<IpAddr>()) {
                (Ok(with_port), _) => (with_port.ip(), Some(with_port.port())),
                (_, Ok(ip)) => (ip, None),
                _ => anyhow::bail!("decoys.addresses: '{entry}' is not an address: use IP or IP:PORT, e.g. 10.0.0.77, 10.0.0.20:5432, [fd00::77]:22"),
            };
            list.push(parsed);
        }
        Ok(Self(list))
    }

    /// `dest` as events carry it: `ip:port` or `[v6]:port`. An entry without a port matches
    /// every port (and a ping, which has none).
    pub fn matches(&self, dest: &str) -> bool {
        if self.0.is_empty() {
            return false;
        }
        let Ok(dest) = dest.parse::<SocketAddr>() else { return false };
        self.0.iter().any(|(ip, port)| *ip == dest.ip() && port.is_none_or(|p| p == dest.port()))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Auto {
    /// A spare-looking private key in ~/.ssh.
    pub ssh: bool,
    /// A backup-looking credentials file in ~/.aws.
    pub aws: bool,
    /// A .env file with fake secrets in the home directory.
    pub env: bool,
}

impl Auto {
    fn kinds(&self) -> Vec<Kind> {
        [(self.ssh, Kind::Ssh), (self.aws, Kind::Aws), (self.env, Kind::Env)].into_iter().filter(|(on, _)| *on).map(|(_, k)| k).collect()
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Ssh,
    Aws,
    Env,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Ssh => "ssh",
            Kind::Aws => "aws",
            Kind::Env => "env",
        }
    }

    /// Folder under the home directory ("" is the home directory itself), the mode to create
    /// it with if it's missing, and the names to pick from. None of the names is one the real
    /// tool loads by itself (ssh tries id_rsa, id_ecdsa, id_ed25519...; the AWS CLI reads
    /// `credentials` and `config`), and no key gets a `.pub` twin, which some key agents load.
    fn place(self) -> (&'static str, u32, &'static [&'static str]) {
        match self {
            Kind::Ssh => (
                ".ssh",
                0o700,
                &[
                    "id_rsa.old", "id_rsa.bak", "id_rsa_backup", "id_ed25519.old", "id_ed25519.bak", "id_ed25519_backup",
                    "id_ecdsa.bak", "deploy_key", "backup_key", "github_deploy_key", "prod_key.pem", "server.pem",
                ],
            ),
            Kind::Aws => (
                ".aws",
                0o755,
                &["credentials.bak", "credentials.old", "credentials.backup", "credentials.orig", "credentials-prod", "credentials_old"],
            ),
            Kind::Env => ("", 0o755, &[".env.backup", ".env.production", ".env.prod", ".env.old", ".env.bak", "prod.env"]),
        }
    }

    /// Random content in the shape of the real thing.
    fn content(self) -> String {
        const UPPER32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const SECRET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        match self {
            Kind::Ssh => {
                let mut blob = b"openssh-key-v1\0".to_vec();
                blob.extend(random_bytes(384));
                let body: Vec<String> = base64(&blob).as_bytes().chunks(70).map(|c| String::from_utf8_lossy(c).into_owned()).collect();
                format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n", body.join("\n"))
            }
            Kind::Aws => format!(
                "[default]\naws_access_key_id = AKIA{}\naws_secret_access_key = {}\nregion = us-east-1\n",
                random_text(UPPER32, 16),
                random_text(SECRET, 40)
            ),
            Kind::Env => format!(
                "# production\nDATABASE_URL=postgres://app:{}@db.internal:5432/app\nAPI_KEY={}\nSECRET_KEY={}\n",
                random_text(ALNUM, 24),
                random_text(ALNUM, 40),
                random_text(ALNUM, 48)
            ),
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct State {
    /// The `dnom classify` that planted the set.
    pid: u32,
    created_ms: u64,
    files: Vec<FileRecord>,
    /// Folders dnom had to create (removed again if empty).
    dirs: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct FileRecord {
    kind: String,
    path: String,
    /// Hash of what dnom wrote: a file that no longer matches is not dnom's to delete.
    check: String,
}

/// The generated decoys of this run. Dropping it removes them.
pub struct Planted {
    state_path: PathBuf,
    home: PathBuf,
    auto: Auto,
    state: State,
}

impl Planted {
    pub fn state_path(state_dir: &Path) -> PathBuf {
        state_dir.join("decoys.json")
    }

    /// Removes what an earlier run left behind, then plants a new set (None: nothing to plant).
    pub fn start(state_dir: &Path, home: &Path, auto: &Auto) -> anyhow::Result<Option<Self>> {
        let state_path = Self::state_path(state_dir);
        match sweep(&state_path) {
            Sweep::Busy(pid) => {
                eprintln!("dnom classify: another dnom classify (pid {pid}) has generated decoys in place; this one plants none");
                return Ok(None);
            }
            Sweep::Removed(n) if n > 0 => {
                eprintln!("dnom classify: removed {n} decoys left by an earlier run that did not stop cleanly");
            }
            _ => {}
        }
        if auto.kinds().is_empty() {
            return Ok(None);
        }
        let mut planted = Self { state_path, home: home.to_path_buf(), auto: auto.clone(), state: State::default() };
        planted.plant()?;
        Ok(Some(planted))
    }

    fn plant(&mut self) -> anyhow::Result<()> {
        self.state = State { pid: std::process::id(), created_ms: now_ms(), files: Vec::new(), dirs: Vec::new() };
        for kind in self.auto.kinds() {
            match plant_one(&self.home, kind, &mut self.state.dirs) {
                Ok(Some(file)) => self.state.files.push(file),
                Ok(None) => eprintln!("dnom classify: no {} decoy planted: every candidate name already exists", kind.name()),
                Err(e) => eprintln!("dnom classify: no {} decoy planted: {e:#}", kind.name()),
            }
            // Saved after every file, so nothing is ever on disk without being remembered.
            self.save()?;
        }
        Ok(())
    }

    fn save(&self) -> anyhow::Result<()> {
        let tmp = self.state_path.with_extension("json.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("write {}", tmp.display()))?;
        file.write_all(&serde_json::to_vec(&self.state)?)?;
        fs::rename(&tmp, &self.state_path)?;
        Ok(())
    }

    pub fn paths(&self) -> Vec<String> {
        self.state.files.iter().map(|f| f.path.clone()).collect()
    }

    /// "3 (ssh, aws, env)"
    pub fn summary(&self) -> String {
        let kinds: Vec<&str> = self.state.files.iter().map(|f| f.kind.as_str()).collect();
        format!("{} ({})", kinds.len(), kinds.join(", "))
    }

    pub fn rotation_due(&self, rotate_days: u64) -> bool {
        rotate_days > 0 && now_ms().saturating_sub(self.state.created_ms) >= rotate_days * 86_400_000
    }

    /// Removes the current set and plants a new one.
    pub fn rotate(&mut self) -> anyhow::Result<()> {
        remove_set(&self.state);
        self.plant()
    }
}

impl Drop for Planted {
    fn drop(&mut self) {
        let (removed, kept) = remove_set(&self.state);
        let _ = fs::remove_file(&self.state_path);
        let kept = if kept > 0 { format!(", {kept} left in place (changed since dnom created them)") } else { String::new() };
        eprintln!("dnom classify: removed {removed} generated decoys{kept}");
    }
}

enum Sweep {
    Nothing,
    Removed(usize),
    Busy(u32),
}

/// Removes the set a previous run recorded, unless that run is still alive.
fn sweep(state_path: &Path) -> Sweep {
    let Ok(text) = fs::read_to_string(state_path) else { return Sweep::Nothing };
    let Ok(state) = serde_json::from_str::<State>(&text) else {
        let _ = fs::remove_file(state_path);
        return Sweep::Nothing;
    };
    if state.pid != std::process::id() && is_running_classify(state.pid) {
        return Sweep::Busy(state.pid);
    }
    let (removed, _) = remove_set(&state);
    let _ = fs::remove_file(state_path);
    Sweep::Removed(removed)
}

fn is_running_classify(pid: u32) -> bool {
    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    comm.trim() == "dnom" && cmdline.split(|b| *b == 0).nth(1) == Some(b"classify".as_slice())
}

/// Creates one decoy of this kind under `home`. None when every candidate name is taken.
fn plant_one(home: &Path, kind: Kind, dirs_created: &mut Vec<String>) -> anyhow::Result<Option<FileRecord>> {
    let (sub, dir_mode, names) = kind.place();
    let dir = if sub.is_empty() { home.to_path_buf() } else { home.join(sub) };
    if !dir.exists() {
        fs::DirBuilder::new().mode(dir_mode).create(&dir).with_context(|| format!("create {}", dir.display()))?;
        dirs_created.push(dir.to_string_lossy().into_owned());
    }
    let dir_times = times_of(&dir);
    let first = random_below(names.len());
    for i in 0..names.len() {
        let path = dir.join(names[(first + i) % names.len()]);
        // create_new: never overwrite, never follow a link to an existing file.
        let mut file = match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("create a file in {}", dir.display())),
        };
        let content = kind.content();
        file.write_all(content.as_bytes())?;
        drop(file);
        // Look old in a listing: a random date 1 to 13 months back. (The inode change time
        // still says when it was really created; that can't be set.)
        let age_s = (30 + random_below(370)) as i64 * 86_400;
        let then = libc::timespec { tv_sec: (now_ms() / 1000) as i64 - age_s, tv_nsec: 0 };
        set_times(&path, [then, then]);
        if let Some(times) = dir_times {
            set_times(&dir, times);
        }
        return Ok(Some(FileRecord { kind: kind.name().into(), path: path.to_string_lossy().into_owned(), check: check_of(content.as_bytes()) }));
    }
    Ok(None)
}

/// Removes the files of a set that are still what dnom wrote, and the folders it created.
/// Returns (removed, left in place because they changed).
fn remove_set(state: &State) -> (usize, usize) {
    let (mut removed, mut kept) = (0, 0);
    for file in &state.files {
        let path = Path::new(&file.path);
        match fs::read(path) {
            Ok(content) if check_of(&content) == file.check => {
                let dir_times = path.parent().and_then(times_of);
                if fs::remove_file(path).is_ok() {
                    removed += 1;
                }
                if let (Some(dir), Some(times)) = (path.parent(), dir_times) {
                    set_times(dir, times);
                }
            }
            Ok(_) => {
                kept += 1;
                eprintln!("dnom classify: decoy {} changed since dnom created it; left in place", file.path);
            }
            Err(_) => {} // already gone
        }
    }
    for dir in &state.dirs {
        let _ = fs::remove_dir(dir); // only if empty
    }
    (removed, kept)
}

fn check_of(content: &[u8]) -> String {
    format!("{:016x}", crate::classify::fnv1a(content))
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// (access, modification) times of a path.
fn times_of(path: &Path) -> Option<[libc::timespec; 2]> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(path).ok()?;
    Some([libc::timespec { tv_sec: m.atime(), tv_nsec: m.atime_nsec() }, libc::timespec { tv_sec: m.mtime(), tv_nsec: m.mtime_nsec() }])
}

fn set_times(path: &Path, times: [libc::timespec; 2]) {
    use std::os::unix::ffi::OsStrExt;
    if let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) {
        unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
    }
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    let mut filled = 0;
    while filled < n {
        let got = unsafe { libc::getrandom(buf[filled..].as_mut_ptr().cast(), n - filled, 0) };
        if got <= 0 {
            // No kernel randomness (not expected on Linux): decoys only need to differ per run.
            let seed = now_ms() ^ ((std::process::id() as u64) << 32);
            for (i, b) in buf[filled..].iter_mut().enumerate() {
                *b = (seed.wrapping_mul(6364136223846793005).wrapping_add(i as u64 * 1442695040888963407) >> 33) as u8;
            }
            break;
        }
        filled += got as usize;
    }
    buf
}

fn random_below(n: usize) -> usize {
    let b = random_bytes(8);
    (u64::from_le_bytes(b.try_into().unwrap_or([0; 8])) % n.max(1) as u64) as usize
}

fn random_text(alphabet: &[u8], n: usize) -> String {
    random_bytes(n).into_iter().map(|b| alphabet[b as usize % alphabet.len()] as char).collect()
}

fn base64(data: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { TABLE[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    const ALL: Auto = Auto { ssh: true, aws: true, env: true };

    /// A fake home with a real-looking ~/.ssh and no ~/.aws, plus a state folder.
    fn fake_home(name: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!("dnom-decoys-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (home, state) = (root.join("home"), root.join("state"));
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::write(home.join(".ssh/id_ed25519"), "THE USER'S OWN KEY").unwrap();
        (home, state)
    }

    fn files_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir).map(|d| d.filter_map(|e| Some(e.ok()?.file_name().to_string_lossy().into_owned())).collect()).unwrap_or_default();
        names.sort();
        names
    }

    #[test]
    fn plants_one_file_per_kind_and_removes_them_when_dropped() {
        let (home, state) = fake_home("plant");
        let planted = Planted::start(&state, &home, &ALL).unwrap().unwrap();
        let paths = planted.paths();
        assert_eq!(planted.summary(), "3 (ssh, aws, env)");

        let (ssh, aws, env) = (Path::new(&paths[0]), Path::new(&paths[1]), Path::new(&paths[2]));
        assert_eq!(ssh.parent().unwrap(), home.join(".ssh"));
        assert_eq!(aws.parent().unwrap(), home.join(".aws"));
        assert_eq!(env.parent().unwrap(), home);
        for (path, kind) in [(ssh, Kind::Ssh), (aws, Kind::Aws), (env, Kind::Env)] {
            assert!(kind.place().2.contains(&path.file_name().unwrap().to_str().unwrap()), "{path:?}");
            assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600, "{path:?}");
            let age = SystemTime::now().duration_since(fs::metadata(path).unwrap().modified().unwrap()).unwrap();
            assert!(age.as_secs() > 29 * 86_400, "looks old in a listing: {path:?}");
        }
        let key = fs::read_to_string(ssh).unwrap();
        assert!(key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA") && key.ends_with("-----END OPENSSH PRIVATE KEY-----\n"), "{key}");
        assert!(key.lines().all(|l| l.len() <= 70));
        let creds = fs::read_to_string(aws).unwrap();
        assert!(creds.contains("aws_access_key_id = AKIA") && creds.contains("aws_secret_access_key = "), "{creds}");
        assert!(fs::read_to_string(env).unwrap().contains("DATABASE_URL=postgres://app:"));

        let state_file = Planted::state_path(&state);
        assert_eq!(fs::metadata(&state_file).unwrap().permissions().mode() & 0o777, 0o600);
        let saved: State = serde_json::from_str(&fs::read_to_string(&state_file).unwrap()).unwrap();
        assert_eq!(saved.files.iter().map(|f| f.path.clone()).collect::<Vec<_>>(), paths);

        drop(planted);
        assert!(paths.iter().all(|p| !Path::new(p).exists()), "decoys removed");
        assert!(!home.join(".aws").exists(), "the folder dnom created is removed");
        assert_eq!(files_in(&home.join(".ssh")), ["id_ed25519"], "the user's own key is untouched");
        assert_eq!(fs::read_to_string(home.join(".ssh/id_ed25519")).unwrap(), "THE USER'S OWN KEY");
        assert!(!state_file.exists());
        fs::remove_dir_all(home.parent().unwrap()).unwrap();
    }

    #[test]
    fn never_overwrites_and_never_deletes_what_it_did_not_write() {
        let (home, state) = fake_home("careful");
        // Every candidate AWS name is already a file of the user's.
        fs::create_dir_all(home.join(".aws")).unwrap();
        for name in Kind::Aws.place().2 {
            fs::write(home.join(".aws").join(name), "MINE").unwrap();
        }
        let planted = Planted::start(&state, &home, &ALL).unwrap().unwrap();
        assert_eq!(planted.summary(), "2 (ssh, env)", "no AWS decoy: all names taken");
        assert!(Kind::Aws.place().2.iter().all(|n| fs::read_to_string(home.join(".aws").join(n)).unwrap() == "MINE"));

        // The user edits the env decoy: it is no longer dnom's to delete.
        let env = planted.paths()[1].clone();
        fs::write(&env, "now the user's notes").unwrap();
        drop(planted);
        assert_eq!(fs::read_to_string(&env).unwrap(), "now the user's notes");
        assert!(home.join(".aws").exists(), "a folder dnom did not create stays");
        assert_eq!(files_in(&home.join(".ssh")), ["id_ed25519"]);
        fs::remove_dir_all(home.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_later_start_removes_what_a_killed_run_left() {
        let (home, state) = fake_home("sweep");
        let killed = Planted::start(&state, &home, &ALL).unwrap().unwrap();
        std::mem::forget(killed); // no cleanup, as after kill -9
        assert_eq!(files_in(&home.join(".ssh")).len(), 2);

        // Decoys switched off since: the leftovers still go, and nothing new is planted.
        assert!(Planted::start(&state, &home, &Auto::default()).unwrap().is_none());
        assert_eq!(files_in(&home.join(".ssh")), ["id_ed25519"]);
        assert!(!home.join(".aws").exists() && !Planted::state_path(&state).exists());
        assert_eq!(files_in(&home), [".ssh"]);
        fs::remove_dir_all(home.parent().unwrap()).unwrap();
    }

    #[test]
    fn rotation_replaces_the_set() {
        let (home, state) = fake_home("rotate");
        let mut planted = Planted::start(&state, &home, &ALL).unwrap().unwrap();
        assert!(!planted.rotation_due(7) && !planted.rotation_due(0));
        planted.state.created_ms -= 8 * 86_400_000;
        assert!(planted.rotation_due(7) && !planted.rotation_due(0), "0 means one set per run");

        let before = fs::read_to_string(&planted.paths()[0]).unwrap();
        planted.rotate().unwrap();
        assert_eq!(planted.paths().len(), 3);
        assert_eq!(files_in(&home.join(".ssh")).len(), 2, "one decoy next to the user's key, not two");
        assert_ne!(fs::read_to_string(&planted.paths()[0]).unwrap(), before, "new content");
        assert!(!planted.rotation_due(7));
        drop(planted);
        assert_eq!(files_in(&home), [".ssh"]);
        fs::remove_dir_all(home.parent().unwrap()).unwrap();
    }

    #[test]
    fn addresses_match_with_or_without_a_port() {
        let list = |entries: &[&str]| Addresses::parse(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let decoys = list(&["10.43.0.77", "10.43.0.20:5432", "127.0.0.1:6379", "fd00::77", "[::1]:6379"]).unwrap();
        for hit in ["10.43.0.77:22", "10.43.0.77:0", "10.43.0.20:5432", "127.0.0.1:6379", "[fd00::77]:443", "[::1]:6379"] {
            assert!(decoys.matches(hit), "{hit}");
        }
        for miss in ["10.43.0.78:22", "10.43.0.20:443", "127.0.0.1:6380", "[::1]:22", "[fd00::78]:443", "not an address", ""] {
            assert!(!decoys.matches(miss), "{miss}");
        }
        assert!(!Addresses::default().matches("10.43.0.77:22"));
        for bad in ["10.43.0", "10.43.0.77:port", "example.com", "10.43.0.0/24", ""] {
            assert!(list(&[bad]).is_err(), "{bad}");
        }
    }

    #[test]
    fn base64_matches_the_standard() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
