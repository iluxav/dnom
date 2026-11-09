//! Policy engine (SPEC §4.5), dry run only: rules in dnom.yaml (`policies:`) combine model
//! answers with episode facts and say which actions they WOULD take. Nothing is executed;
//! dnom is observe-only in this PoC.
//!
//! Conditions (`when:`) use a small language:
//!   credential_access >= 0.85 and (exfiltration >= 0.6 or "new_exe" in flags)
//!   response == "contain"          response.contain >= 0.3       not fits_baseline > 0.5
//! Fields: every question id (noul/score: number, choice: chosen option as a string,
//! `<choice>.<option>`: that option's probability), plus episode facts: `flags` (list),
//! `files.credentials` / `files.persistence` / `files.system_binaries` / `files.temp`
//! (counts), `net.new` / `net.total` (destination counts), `procs`, `uid`.
//! A rule that needs a model answer the episode doesn't have (no backend, failed call)
//! does not match.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    assess::Answer,
    questions::{AssessmentConfig, QuestionType},
};

const EPISODE_NUMBERS: &[&str] = &[
    "files.credentials",
    "files.persistence",
    "files.system_binaries",
    "files.temp",
    "net.new",
    "net.total",
    "procs",
    "uid",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Alert,
    KillTree,
    BlockNet,
    QuarantineExe,
}

impl Action {
    pub fn name(self) -> &'static str {
        match self {
            Action::Alert => "alert",
            Action::KillTree => "kill_tree",
            Action::BlockNet => "block_net",
            Action::QuarantineExe => "quarantine_exe",
        }
    }

    /// Actions that touch processes or files; skipped for protected programs.
    fn is_destructive(self) -> bool {
        self != Action::Alert
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub name: String,
    pub when: String,
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Must stay true: this PoC never executes actions.
    #[serde(default = "yes")]
    pub dry_run: bool,
    /// Program names (comm or exe basename of the episode root) that destructive actions
    /// would never touch.
    #[serde(default = "default_protected")]
    pub protected: Vec<String>,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}

fn yes() -> bool {
    true
}

fn default_protected() -> Vec<String> {
    ["sshd", "sshd-session", "systemd", "init", "dnom", "falco"].map(String::from).to_vec()
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self { dry_run: true, protected: default_protected(), rules: Vec::new() }
    }
}

/// A rule whose condition held for an episode.
#[derive(Debug, Clone)]
pub struct Match {
    pub rule: String,
    pub actions: Vec<Action>,
    /// Destructive actions would be skipped: the episode root is a protected program.
    pub protected: bool,
    /// Values of the fields the condition used, for the report.
    pub values: Vec<(String, String)>,
}

impl Match {
    pub fn to_json(&self) -> Value {
        json!({
            "rule": self.rule,
            "actions": self.actions.iter().map(|a| a.name()).collect::<Vec<_>>(),
            "dry_run": true,
            "protected": self.protected,
            "values": self.values.iter().cloned().collect::<BTreeMap<_, _>>(),
        })
    }
}

/// Policies parsed and type-checked against the configured questions.
#[derive(Debug)]
pub struct Policies {
    protected: Vec<String>,
    rules: Vec<(PolicyRule, Expr)>,
}

impl PolicyConfig {
    pub fn compile(&self, assessment: &AssessmentConfig) -> anyhow::Result<Policies> {
        ensure!(
            self.dry_run,
            "policies.dry_run: false is not supported; this PoC only reports what it would do"
        );
        let types = FieldTypes::new(assessment);
        let mut names = std::collections::HashSet::new();
        let mut rules = Vec::new();
        for rule in &self.rules {
            let at = format!("policies.rules.{}", rule.name);
            ensure!(!rule.name.trim().is_empty(), "policies.rules: every rule needs a name");
            ensure!(names.insert(rule.name.as_str()), "policies.rules: duplicate name '{}'", rule.name);
            ensure!(!rule.actions.is_empty(), "{at}: needs at least one action");
            let expr = parse(&rule.when).map_err(|e| anyhow!("{at}: when: {e}"))?;
            types.check(&expr).map_err(|e| anyhow!("{at}: when: {e}"))?;
            rules.push((rule.clone(), expr));
        }
        Ok(Policies { protected: self.protected.clone(), rules })
    }
}

impl Policies {
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Rules that match this episode. `answers` is None when no model was asked.
    pub fn evaluate(&self, episode: &Value, answers: Option<&BTreeMap<String, Answer>>) -> Vec<Match> {
        let ctx = Ctx { episode, answers };
        let root = &episode["root"];
        let root_names = [
            root["exe"].as_str().map(|e| e.rsplit('/').next().unwrap_or(e)).unwrap_or(""),
            root["comm"].as_str().unwrap_or(""),
        ];
        let protected = self.protected.iter().any(|p| root_names.contains(&p.as_str()));
        self.rules
            .iter()
            .filter(|(_, expr)| expr.eval(&ctx) == Some(true))
            .map(|(rule, expr)| {
                let mut fields = Vec::new();
                expr.fields(&mut fields);
                fields.dedup();
                Match {
                    rule: rule.name.clone(),
                    actions: rule.actions.clone(),
                    protected: protected && rule.actions.iter().any(|a| a.is_destructive()),
                    values: fields.into_iter().map(|f| (f.clone(), ctx.get(&f).display())).collect(),
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------------------------
// Condition language
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Operand {
    Num(f64),
    Str(String),
    Field(String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CmpOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

#[derive(Debug, Clone, PartialEq)]
enum Expr {
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
    Cmp(Operand, CmpOp, Operand),
    /// `"literal" in field` (field is a list, e.g. flags).
    In(String, String),
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(f64),
    Str(String),
    Ident(String),
    Op(CmpOp),
    LParen,
    RParen,
}

fn tokenize(s: &str) -> anyhow::Result<Vec<Tok>> {
    let mut out = Vec::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            c if c.is_whitespace() => i += 1,
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '"' | '\'' => {
                let end = chars[i + 1..]
                    .iter()
                    .position(|&d| d == c)
                    .ok_or_else(|| anyhow!("unclosed string starting at column {}", i + 1))?;
                out.push(Tok::Str(chars[i + 1..i + 1 + end].iter().collect()));
                i += end + 2;
            }
            '>' | '<' | '=' | '!' => {
                let two: String = chars[i..(i + 2).min(chars.len())].iter().collect();
                let (op, len) = match two.as_str() {
                    ">=" => (CmpOp::Ge, 2),
                    "<=" => (CmpOp::Le, 2),
                    "==" => (CmpOp::Eq, 2),
                    "!=" => (CmpOp::Ne, 2),
                    _ if c == '>' => (CmpOp::Gt, 1),
                    _ if c == '<' => (CmpOp::Lt, 1),
                    _ => bail!("unknown operator at column {} (use ==, !=, >, >=, <, <=)", i + 1),
                };
                out.push(Tok::Op(op));
                i += len;
            }
            c if c.is_ascii_digit() || (c == '.' && chars.get(i + 1).is_some_and(|d| d.is_ascii_digit())) => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    i += 1;
                }
                let text: String = chars[start..i].iter().collect();
                out.push(Tok::Num(text.parse().map_err(|_| anyhow!("bad number '{text}'"))?));
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_' || chars[i] == '.') {
                    i += 1;
                }
                out.push(Tok::Ident(chars[start..i].iter().collect()));
            }
            _ => bail!("unexpected '{c}' at column {}", i + 1),
        }
    }
    Ok(out)
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn keyword(&mut self, word: &str) -> bool {
        if matches!(self.peek(), Some(Tok::Ident(w)) if w == word) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn or(&mut self) -> anyhow::Result<Expr> {
        let mut left = self.and()?;
        while self.keyword("or") {
            left = Expr::Or(Box::new(left), Box::new(self.and()?));
        }
        Ok(left)
    }

    fn and(&mut self) -> anyhow::Result<Expr> {
        let mut left = self.unary()?;
        while self.keyword("and") {
            left = Expr::And(Box::new(left), Box::new(self.unary()?));
        }
        Ok(left)
    }

    fn unary(&mut self) -> anyhow::Result<Expr> {
        if self.keyword("not") {
            return Ok(Expr::Not(Box::new(self.unary()?)));
        }
        if self.peek() == Some(&Tok::LParen) {
            self.pos += 1;
            let e = self.or()?;
            ensure!(self.next() == Some(Tok::RParen), "missing )");
            return Ok(e);
        }
        let left = self.operand()?;
        if self.keyword("in") {
            let Operand::Str(lit) = left else { bail!("`in` needs a quoted string on the left, e.g. \"new_exe\" in flags") };
            let Some(Tok::Ident(field)) = self.next() else { bail!("`in` needs a field on the right, e.g. flags") };
            return Ok(Expr::In(lit, field));
        }
        match self.next() {
            Some(Tok::Op(op)) => Ok(Expr::Cmp(left, op, self.operand()?)),
            _ => bail!("expected a comparison (==, !=, >, >=, <, <=) or `in` after {left:?}"),
        }
    }

    fn operand(&mut self) -> anyhow::Result<Operand> {
        match self.next() {
            Some(Tok::Num(n)) => Ok(Operand::Num(n)),
            Some(Tok::Str(s)) => Ok(Operand::Str(s)),
            Some(Tok::Ident(w)) if ["and", "or", "not", "in"].contains(&w.as_str()) => {
                bail!("unexpected keyword '{w}'")
            }
            Some(Tok::Ident(w)) => Ok(Operand::Field(w)),
            Some(t) => bail!("unexpected {t:?}"),
            None => bail!("condition ends too early"),
        }
    }
}

fn parse(s: &str) -> anyhow::Result<Expr> {
    let mut p = Parser { toks: tokenize(s)?, pos: 0 };
    ensure!(!p.toks.is_empty(), "empty condition");
    let e = p.or()?;
    ensure!(p.pos == p.toks.len(), "unexpected text after the condition: {:?}", &p.toks[p.pos..]);
    Ok(e)
}

// ---------------------------------------------------------------------------------------------
// Type checking against the configured questions
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Ty {
    Num,
    /// A choice answer; the options it can equal.
    Choice(Vec<String>),
    List,
}

struct FieldTypes(BTreeMap<String, Ty>);

impl FieldTypes {
    fn new(assessment: &AssessmentConfig) -> Self {
        let mut m = BTreeMap::new();
        for q in &assessment.questions {
            match q.kind {
                QuestionType::Noul | QuestionType::Score => {
                    m.insert(q.id.clone(), Ty::Num);
                }
                QuestionType::Choice => {
                    let names: Vec<String> = q.options.iter().map(|o| o.name.clone()).collect();
                    for n in &names {
                        m.insert(format!("{}.{n}", q.id), Ty::Num);
                    }
                    m.insert(q.id.clone(), Ty::Choice(names));
                }
            }
        }
        for f in EPISODE_NUMBERS {
            m.insert(f.to_string(), Ty::Num);
        }
        m.insert("flags".into(), Ty::List);
        Self(m)
    }

    fn field(&self, name: &str) -> anyhow::Result<&Ty> {
        self.0.get(name).ok_or_else(|| {
            anyhow!("unknown field '{name}'; known: {}", self.0.keys().cloned().collect::<Vec<_>>().join(", "))
        })
    }

    fn check(&self, e: &Expr) -> anyhow::Result<()> {
        match e {
            Expr::And(a, b) | Expr::Or(a, b) => {
                self.check(a)?;
                self.check(b)
            }
            Expr::Not(a) => self.check(a),
            Expr::In(_, field) => {
                ensure!(self.field(field)? == &Ty::List, "'{field}' is not a list; `in` works with flags");
                Ok(())
            }
            Expr::Cmp(l, op, r) => {
                let ty = |o: &Operand| -> anyhow::Result<Ty> {
                    Ok(match o {
                        Operand::Num(_) => Ty::Num,
                        Operand::Str(_) => Ty::Choice(Vec::new()),
                        Operand::Field(f) => self.field(f)?.clone(),
                    })
                };
                match (ty(l)?, ty(r)?) {
                    (Ty::Num, Ty::Num) => Ok(()),
                    (Ty::Choice(opts), Ty::Choice(other)) => {
                        ensure!(matches!(op, CmpOp::Eq | CmpOp::Ne), "choices can only be compared with == or !=");
                        // `response == "contian"` would never match; catch the typo here.
                        for (lit, options) in [(r, &opts), (l, &other)] {
                            if let Operand::Str(s) = lit
                                && !options.is_empty()
                                && !options.contains(s)
                            {
                                bail!("'{s}' is not an option ({})", options.join(", "));
                            }
                        }
                        Ok(())
                    }
                    (Ty::List, _) | (_, Ty::List) => bail!("use `\"name\" in flags` to test flags"),
                    _ => bail!("can't compare a number with a string"),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Evaluation (three-valued: None = needs an answer this episode doesn't have)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Val {
    Num(f64),
    Str(String),
    List(Vec<String>),
    Missing,
}

impl Val {
    fn display(&self) -> String {
        match self {
            Val::Num(n) if n.fract() == 0.0 => format!("{n:.0}"),
            Val::Num(n) => format!("{n:.2}"),
            Val::Str(s) => s.clone(),
            Val::List(l) => l.join(","),
            Val::Missing => "?".into(),
        }
    }
}

struct Ctx<'a> {
    episode: &'a Value,
    answers: Option<&'a BTreeMap<String, Answer>>,
}

impl Ctx<'_> {
    fn get(&self, field: &str) -> Val {
        let ep = self.episode;
        let count = |v: &Value| v.as_array().map_or(0, |a| a.len()) as f64;
        match field {
            "flags" => Val::List(
                ep["flags"].as_array().into_iter().flatten().filter_map(|f| f.as_str()).map(String::from).collect(),
            ),
            "net.total" => Val::Num(count(&ep["network"])),
            "net.new" => Val::Num(
                ep["network"].as_array().into_iter().flatten().filter(|n| n["new_destination"] == true).count() as f64,
            ),
            "procs" => Val::Num(count(&ep["tree"])),
            "uid" => ep["root"]["uid"].as_f64().map_or(Val::Missing, Val::Num),
            f if f.starts_with("files.") => Val::Num(count(&ep["files"][&f["files.".len()..]])),
            f => {
                let Some(answers) = self.answers else { return Val::Missing };
                if let Some(a) = answers.get(f) {
                    return match a {
                        Answer::Noul { noul } => Val::Num(*noul),
                        Answer::Score { score, .. } => Val::Num(*score),
                        Answer::Choice { choice, .. } => Val::Str(choice.clone()),
                    };
                }
                // <choice>.<option>: that option's probability.
                if let Some((q, opt)) = f.split_once('.')
                    && let Some(Answer::Choice { probabilities, .. }) = answers.get(q)
                {
                    return Val::Num(probabilities.get(opt).copied().unwrap_or(0.0));
                }
                Val::Missing
            }
        }
    }

    fn operand(&self, o: &Operand) -> Val {
        match o {
            Operand::Num(n) => Val::Num(*n),
            Operand::Str(s) => Val::Str(s.clone()),
            Operand::Field(f) => self.get(f),
        }
    }
}

impl Expr {
    fn eval(&self, ctx: &Ctx) -> Option<bool> {
        match self {
            Expr::And(a, b) => match (a.eval(ctx), b.eval(ctx)) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            },
            Expr::Or(a, b) => match (a.eval(ctx), b.eval(ctx)) {
                (Some(true), _) | (_, Some(true)) => Some(true),
                (Some(false), Some(false)) => Some(false),
                _ => None,
            },
            Expr::Not(a) => a.eval(ctx).map(|v| !v),
            Expr::In(lit, field) => match ctx.get(field) {
                Val::List(items) => Some(items.contains(lit)),
                _ => None,
            },
            Expr::Cmp(l, op, r) => match (ctx.operand(l), ctx.operand(r)) {
                (Val::Num(a), Val::Num(b)) => Some(match op {
                    CmpOp::Eq => a == b,
                    CmpOp::Ne => a != b,
                    CmpOp::Gt => a > b,
                    CmpOp::Ge => a >= b,
                    CmpOp::Lt => a < b,
                    CmpOp::Le => a <= b,
                }),
                (Val::Str(a), Val::Str(b)) => Some(match op {
                    CmpOp::Eq => a == b,
                    CmpOp::Ne => a != b,
                    _ => return None,
                }),
                _ => None,
            },
        }
    }

    fn fields(&self, out: &mut Vec<String>) {
        match self {
            Expr::And(a, b) | Expr::Or(a, b) => {
                a.fields(out);
                b.fields(out);
            }
            Expr::Not(a) => a.fields(out),
            Expr::In(_, f) => out.push(f.clone()),
            Expr::Cmp(l, _, r) => {
                for o in [l, r] {
                    if let Operand::Field(f) = o
                        && !out.contains(f)
                    {
                        out.push(f.clone());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policies(yaml: &str) -> anyhow::Result<Policies> {
        let c: PolicyConfig = serde_saphyr::from_str(yaml).unwrap();
        c.compile(&AssessmentConfig::default())
    }

    fn noul(p: f64) -> Answer {
        Answer::Noul { noul: p }
    }

    fn answers(cred: f64, persist: f64, exfil: f64, lateral: f64, normal: f64, response: &str) -> BTreeMap<String, Answer> {
        let mut probabilities = BTreeMap::new();
        for o in ["ignore", "watch", "alert", "contain"] {
            probabilities.insert(o.to_string(), if o == response { 0.6 } else { 0.1 });
        }
        BTreeMap::from([
            ("credential_access".into(), noul(cred)),
            ("persistence".into(), noul(persist)),
            ("exfiltration".into(), noul(exfil)),
            ("lateral_movement".into(), noul(lateral)),
            ("fits_baseline".into(), noul(normal)),
            ("response".into(), Answer::Choice { choice: response.into(), confidence: 0.6, probabilities }),
        ])
    }

    fn episode(exe: &str, creds: &[&str], new_dest: bool, flags: &[&str]) -> Value {
        json!({
            "root": { "exe": exe, "uid": 1000 },
            "files": { "credentials": creds },
            "network": [{ "dest": "203.0.113.7:443", "by": "curl", "new_destination": new_dest }],
            "flags": flags,
            "tree": [{}, {}],
        })
    }

    /// The rules shipped in dnom.yaml.
    fn shipped() -> Policies {
        let c: crate::config::Config = serde_saphyr::from_str(include_str!("../../dnom.yaml")).unwrap();
        c.policies.compile(&c.assessment).unwrap()
    }

    fn names(m: &[Match]) -> Vec<&str> {
        m.iter().map(|m| m.rule.as_str()).collect()
    }

    #[test]
    fn shipped_rules_on_real_runs() {
        let p = shipped();
        // fake-exfil (Jev scores from the live Falco run): caught.
        let fake = episode("/usr/bin/make", &["/tmp/x/.ssh/id_ed25519"], true, &["new_exe"]);
        let hits = p.evaluate(&fake, Some(&answers(0.97, 0.84, 0.96, 0.06, 0.08, "alert")));
        assert!(names(&hits).contains(&"credential-theft"), "{:?}", names(&hits));
        assert!(names(&hits).contains(&"credentials-then-new-destination"));
        // omanote git push over ssh (exfil 0.96 but normal 0.71): no rule.
        let git = episode("/usr/bin/omanote", &["~/.ssh/id_ed25519"], false, &[]);
        assert!(p.evaluate(&git, Some(&answers(0.69, 0.07, 0.96, 0.84, 0.71, "ignore"))).is_empty());
        // ssh -T git@github.com: no rule.
        let ssh = episode("/usr/bin/ssh", &["~/.ssh/id_ed25519"], false, &[]);
        assert!(p.evaluate(&ssh, Some(&answers(0.74, 0.05, 0.3, 0.89, 0.83, "ignore"))).is_empty());
        // sudo reading /etc/shadow from a new program tree (cred 0.79, normal 0.69): no rule.
        let sudo = episode("/usr/bin/make", &["/etc/shadow"], false, &["new_exe"]);
        assert!(p.evaluate(&sudo, Some(&answers(0.79, 0.07, 0.14, 0.06, 0.69, "watch"))).is_empty());
    }

    #[test]
    fn model_independent_rule_works_without_answers() {
        let p = shipped();
        let fake = episode("/usr/bin/make", &["/tmp/x/.ssh/id_ed25519"], true, &[]);
        // No backend (or the call failed): only rules that need no model answer can match.
        assert_eq!(names(&p.evaluate(&fake, None)), ["credentials-then-new-destination"]);
    }

    #[test]
    fn language() {
        let p = policies(
            r#"
rules:
  - { name: a, when: 'credential_access >= 0.8 and not fits_baseline > 0.5', actions: [alert] }
  - { name: b, when: '"new_exe" in flags or (net.new > 0 and files.credentials >= 1)', actions: [alert] }
  - { name: c, when: response == "contain" or response.contain >= 0.5, actions: [alert, kill_tree] }
"#,
        )
        .unwrap();
        let ep = episode("/usr/bin/sshd", &["/etc/shadow"], true, &[]);
        let hits = p.evaluate(&ep, Some(&answers(0.9, 0.1, 0.1, 0.1, 0.2, "contain")));
        assert_eq!(names(&hits), ["a", "b", "c"]);
        // sshd is protected: kill_tree would be skipped; alert-only rules are not marked.
        assert!(hits[2].protected && !hits[0].protected);
        assert_eq!(hits[0].values, [("credential_access".into(), "0.90".into()), ("fits_baseline".into(), "0.20".into())]);
        // Missing answers never make `not` true.
        assert!(p.evaluate(&episode("/x", &[], false, &[]), None).is_empty());
    }

    #[test]
    fn rejects_bad_rules() {
        let bad = [
            ("credential_acess >= 0.8", "unknown field"),
            ("response == \"contian\"", "not an option"),
            ("response > 0.5", "can't compare"),
            ("flags == 1", "in flags"),
            ("\"x\" in uid", "not a list"),
            ("credential_access >= ", "ends too early"),
            ("(credential_access >= 0.8", "missing )"),
            ("credential_access >= 0.8 fits_baseline", "unexpected text"),
            ("credential_access => 0.8", "unknown operator"),
        ];
        for (when, want) in bad {
            let yaml = format!("rules:\n  - {{name: r, when: '{}', actions: [alert]}}\n", when.replace('\'', "''"));
            let err = policies(&yaml).err().map(|e| e.to_string()).unwrap_or_default();
            assert!(err.contains(want), "{when:?}: got {err:?}, want {want:?}");
        }
        assert!(policies("dry_run: false").unwrap_err().to_string().contains("not supported"));
        assert!(policies("rules:\n  - {name: r, when: 'uid == 0', actions: []}").is_err());
        assert!(serde_saphyr::from_str::<PolicyConfig>("rules:\n  - {name: r, when: 'uid == 0', actions: [nuke]}").is_err());
    }
}
