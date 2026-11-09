//! Extra episode signals for cloud / supply-chain shaped activity.
//!
//! All pattern based and best effort: they raise a flag so the pre-filter sends the episode
//! to the model, which makes the final judgement. They never act on their own.

/// Labels a destination that is a cloud metadata or control-plane endpoint.
/// IMDS is the one with a fixed address; the rest are matched by hostname when dnom later
/// records connection hostnames (today it only has IPs, so those return None).
pub fn cloud_endpoint(dest: &str) -> Option<&'static str> {
    let host = dest.rsplit_once(':').map(|(h, _)| h).unwrap_or(dest);
    // Instance Metadata Service (AWS/GCP/Azure all use this link-local address).
    if host == "169.254.169.254" || host == "[fd00:ec2::254]" || host == "fd00:ec2::254" {
        return Some("imds");
    }
    None
}

/// True if a command line both decodes data and feeds it to an interpreter, the classic
/// way to hide a payload (`echo <b64> | base64 -d | python3`, `python3 -c "exec(b64decode(...))"`).
pub fn encoded_exec(argv: &str) -> bool {
    let lower = argv.to_ascii_lowercase();
    let decodes = lower.contains("base64 -d")
        || lower.contains("base64 --decode")
        || lower.contains("base64 -d -")
        || lower.contains("b64decode")
        || lower.contains("openssl enc -d")
        || lower.contains("| base64")
        || lower.contains("xxd -r");
    let interprets = ["python", "python3", "node", "perl", "ruby", "sh -c", "bash -c", "eval ", "exec("]
        .iter()
        .any(|p| lower.contains(p));
    // `python3 -c` with an inline decode is a single-process match.
    let inline = (lower.contains("-c ") || lower.contains("-e "))
        && (lower.contains("b64decode") || lower.contains("base64") || lower.contains("fromcharcode"));
    (decodes && interprets) || inline
}

/// Programs that normally should not spawn an interactive shell. A shell started by one of
/// these is the signal behind the `app_spawned_shell` flag: a web service (node, a parser)
/// or a package install step dropping to a shell is how injected commands run.
pub const NON_INTERACTIVE_PARENTS: &[&str] = &[
    // package managers / build + install steps
    "npm", "npx", "node", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "cargo", "gem", "composer",
    "make", "gcc", "cc", "go", "mvn", "gradle",
    // long-running app / web servers
    "gunicorn", "uwsgi", "uvicorn", "puma", "unicorn", "php-fpm", "httpd", "nginx", "java",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_endpoints() {
        assert_eq!(cloud_endpoint("169.254.169.254:80"), Some("imds"));
        assert_eq!(cloud_endpoint("10.0.0.1:443"), None);
    }

    #[test]
    fn encoded_execs() {
        assert!(encoded_exec("sh -c echo aGVsbG8= | base64 -d | python3"));
        assert!(encoded_exec("python3 -c import base64; exec(base64.b64decode('...'))"));
        assert!(encoded_exec("node -e eval(Buffer.from('...','base64').toString())"));
        assert!(!encoded_exec("python3 app.py --serve"));
        assert!(!encoded_exec("base64 /etc/hostname"));
        assert!(!encoded_exec("git commit -m update"));
    }
}
