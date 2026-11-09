//! Assessor (SPEC §4.4, §6, §7): asks the configured questions (`assessment:` in dnom.yaml)
//! about an episode. `jev` calls TypeSafe's System One API; `local` emulates it with Ollama.

use std::{collections::BTreeMap, time::Duration};

use anyhow::{Context as _, anyhow, bail, ensure};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{
    backends::BackendDef,
    questions::{AssessmentConfig, Question, QuestionType},
};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Answer {
    Noul {
        noul: f64,
    },
    Choice {
        choice: String,
        confidence: f64,
        probabilities: BTreeMap<String, f64>,
    },
    /// `score` is the probability-weighted level (0 = first level); probabilities are keyed
    /// by level index ("0", "1", ...), as Jev returns them.
    Score {
        score: f64,
        confidence: f64,
        probabilities: BTreeMap<String, f64>,
    },
}

pub struct Assessment {
    /// Model name that actually answered.
    pub model: String,
    pub answers: BTreeMap<String, Answer>,
    /// Quality notes, e.g. low yes/no probability mass from the local model.
    pub notes: Vec<String>,
    pub input_tokens: Option<u64>,
}

pub trait Backend {
    /// Backend name from dnom.yaml, e.g. "jev".
    fn name(&self) -> &str;
    fn assess(&self, episode: &Value) -> anyhow::Result<Assessment>;
}

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(timeout))
        .build()
        .into()
}

fn post_json(agent: &ureq::Agent, url: &str, auth: Option<&str>, body: &Value) -> anyhow::Result<Value> {
    let mut req = agent.post(url);
    if let Some(key) = auth {
        req = req.header("Authorization", format!("Bearer {key}"));
    }
    let mut resp = req.send_json(body).with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    let text = resp.body_mut().read_to_string().context("read response body")?;
    if !status.is_success() {
        bail!("POST {url}: HTTP {status}: {}", text.chars().take(500).collect::<String>());
    }
    serde_json::from_str(&text).with_context(|| format!("parse JSON from {url}"))
}

// ---------------------------------------------------------------------------------------------
// Jev (TypeSafe System One API)
// ---------------------------------------------------------------------------------------------

pub struct Jev {
    name: String,
    agent: ureq::Agent,
    url: String,
    key: Option<String>,
    model: String,
    assessment: AssessmentConfig,
    /// `questions` object of the request, built once.
    questions_json: Value,
}

impl Jev {
    /// Any System One server (Jev, or Kev / Von running locally). `model` overrides the
    /// backend's configured model.
    pub fn new(
        name: &str,
        def: &BackendDef,
        model: Option<&str>,
        assessment: AssessmentConfig,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            name: name.to_string(),
            agent: agent(Duration::from_secs(def.timeout_secs())),
            url: format!("{}/v1/systemone", def.url.trim_end_matches('/')),
            key: def.api_key().with_context(|| format!("backend {name}"))?,
            model: model.unwrap_or(&def.model).to_string(),
            questions_json: Value::Object(
                assessment.questions.iter().map(|q| (q.id.clone(), q.to_jev())).collect(),
            ),
            assessment,
        })
    }
}

/// Reads one Jev answer, checking its type matches the question.
fn parse_jev_answer(q: &Question, a: &Value) -> anyhow::Result<Answer> {
    let num = |field: &str| {
        a[field].as_f64().ok_or_else(|| anyhow!("jev: answer '{}' has no {field}", q.id))
    };
    let probabilities =
        || -> BTreeMap<String, f64> { serde_json::from_value(a["probabilities"].clone()).unwrap_or_default() };
    Ok(match q.kind {
        QuestionType::Noul => Answer::Noul { noul: num("noul")? },
        QuestionType::Choice => Answer::Choice {
            choice: a["choice"]
                .as_str()
                .ok_or_else(|| anyhow!("jev: answer '{}' has no choice", q.id))?
                .to_string(),
            confidence: a["confidence"].as_f64().unwrap_or(0.0),
            probabilities: probabilities(),
        },
        QuestionType::Score => Answer::Score {
            score: num("score")?,
            confidence: a["confidence"].as_f64().unwrap_or(0.0),
            probabilities: probabilities(),
        },
    })
}

impl Backend for Jev {
    fn name(&self) -> &str {
        &self.name
    }

    fn assess(&self, episode: &Value) -> anyhow::Result<Assessment> {
        let body = json!({
            "model": self.model,
            "state": { "context": self.assessment.context, "episode": episode },
            "questions": self.questions_json,
        });
        let resp = post_json(&self.agent, &self.url, self.key.as_deref(), &body)?;
        let mut answers = BTreeMap::new();
        for q in &self.assessment.questions {
            answers.insert(q.id.clone(), parse_jev_answer(q, &resp["answers"][&q.id])?);
        }
        Ok(Assessment {
            model: resp["model"].as_str().unwrap_or(&self.model).to_string(),
            answers,
            notes: Vec::new(),
            input_tokens: resp["usage"]["input_tokens"].as_u64(),
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Local (Ollama): one single-token answer per question, probability from top_logprobs
// ---------------------------------------------------------------------------------------------

pub struct Local {
    name: String,
    agent: ureq::Agent,
    url: String,
    key: Option<String>,
    model: String,
    assessment: AssessmentConfig,
}

/// Choice options and score levels are answered with one letter each, A to Z.
const MAX_LETTERS: usize = 26;

fn letter(i: usize) -> String {
    char::from(b'A' + i as u8).to_string()
}

impl Local {
    /// An Ollama server. `model` overrides the backend's configured model.
    pub fn new(
        name: &str,
        def: &BackendDef,
        model: Option<&str>,
        assessment: AssessmentConfig,
    ) -> anyhow::Result<Self> {
        for q in &assessment.questions {
            let n = q.options.len().max(q.levels.len());
            ensure!(
                n <= MAX_LETTERS,
                "--backend local answers with one letter per option, so question '{}' can have at \
                 most {MAX_LETTERS} options or levels (it has {n})",
                q.id
            );
        }
        Ok(Self {
            name: name.to_string(),
            // The first call may load the model from disk (about 45 s for the 27B model).
            agent: agent(Duration::from_secs(def.timeout_secs())),
            url: format!("{}/api/chat", def.url.trim_end_matches('/')),
            key: def.api_key().with_context(|| format!("backend {name}"))?,
            model: model.unwrap_or(&def.model).to_string(),
            assessment,
        })
    }

    fn prompt(question: &Question) -> String {
        let lettered = |title: &str, items: Vec<String>| {
            let mut s = format!("Question: {}\n{title}:\n", question.instructions);
            for (i, item) in items.iter().enumerate() {
                s.push_str(&format!("{}) {item}\n", letter(i)));
            }
            s.push_str("Answer with the letter only.");
            s
        };
        match question.kind {
            QuestionType::Noul => format!(
                "Statement: {}\nTrue means: {}\nFalse means: {}\n\
                 Is the statement true for this episode? Answer yes or no.",
                question.instructions,
                question.yes_means.as_deref().unwrap_or(""),
                question.no_means.as_deref().unwrap_or(""),
            ),
            QuestionType::Choice => lettered(
                "Options",
                question
                    .options
                    .iter()
                    .map(|o| match &o.means {
                        Some(m) => format!("{}: {m}", o.name),
                        None => o.name.clone(),
                    })
                    .collect(),
            ),
            QuestionType::Score => lettered("Levels, lowest first", question.levels.clone()),
        }
    }

    /// Episode first, question last, so Ollama reuses the cached prefix for every question.
    fn ask(&self, episode_text: &str, question: &Question) -> anyhow::Result<Value> {
        let body = json!({
            "model": self.model,
            "stream": false,
            "think": false,
            "logprobs": true,
            "top_logprobs": 20,
            "keep_alive": "30m",
            "options": { "temperature": 0, "num_predict": 1, "num_ctx": 8192 },
            "messages": [
                { "role": "system", "content": format!("You are a security analyst. {} Answer exactly as asked, with a single word or letter.", self.assessment.context) },
                { "role": "user", "content": format!("Episode:\n```json\n{episode_text}\n```\n\n{}", Self::prompt(question)) },
            ],
        });
        post_json(&self.agent, &self.url, self.key.as_deref(), &body)
    }
}

/// Sums probability over spellings of each label ("yes", "Yes", " yes", ...).
fn label_mass(resp: &Value, normalize: impl Fn(&str) -> Option<String>) -> BTreeMap<String, f64> {
    let mut mass = BTreeMap::new();
    let top = resp["logprobs"][0]["top_logprobs"].as_array().cloned().unwrap_or_default();
    for t in top {
        let (Some(token), Some(lp)) = (t["token"].as_str(), t["logprob"].as_f64()) else {
            continue;
        };
        if let Some(label) = normalize(token) {
            *mass.entry(label).or_insert(0.0) += lp.exp();
        }
    }
    mass
}

/// Probability of each of the first `n` answer letters (A, B, ...), normalised over those
/// letters, plus the raw mass they had (a quality signal).
fn letter_probs(resp: &Value, n: usize) -> (Vec<f64>, f64) {
    let mass = label_mass(resp, |t| {
        let t = t.trim().trim_end_matches(')').to_uppercase();
        (0..n).map(letter).find(|l| *l == t)
    });
    let total: f64 = mass.values().sum();
    let probs = (0..n)
        .map(|i| if total > 0.0 { mass.get(&letter(i)).copied().unwrap_or(0.0) / total } else { 0.0 })
        .collect();
    (probs, total)
}

impl Backend for Local {
    fn name(&self) -> &str {
        &self.name
    }

    fn assess(&self, episode: &Value) -> anyhow::Result<Assessment> {
        let episode_text = serde_json::to_string_pretty(episode)?;
        let mut answers = BTreeMap::new();
        let mut notes = Vec::new();
        let mut model = self.model.clone();
        let mut input_tokens = 0;
        for q in &self.assessment.questions {
            let resp = self.ask(&episode_text, q)?;
            if let Some(m) = resp["model"].as_str() {
                model = m.to_string();
            }
            input_tokens += resp["prompt_eval_count"].as_u64().unwrap_or(0);
            let content = resp["message"]["content"].as_str().unwrap_or("").trim().to_lowercase();
            let answer = match q.kind {
                QuestionType::Noul => {
                    let mass = label_mass(&resp, |t| {
                        let t = t.trim().to_lowercase();
                        (t == "yes" || t == "no").then_some(t)
                    });
                    let yes = mass.get("yes").copied().unwrap_or(0.0);
                    let no = mass.get("no").copied().unwrap_or(0.0);
                    let p = if yes + no > 0.0 {
                        yes / (yes + no)
                    } else {
                        notes.push(format!("{}: no yes/no tokens, used text {content:?}", q.id));
                        if content.starts_with("yes") { 1.0 } else { 0.0 }
                    };
                    if yes + no < 0.5 {
                        notes.push(format!("{}: low yes/no mass {:.2}", q.id, yes + no));
                    }
                    Answer::Noul { noul: p }
                }
                QuestionType::Choice => {
                    let (probs, total) = letter_probs(&resp, q.options.len());
                    if total < 0.5 {
                        notes.push(format!("{}: low option mass {total:.2}", q.id));
                    }
                    let probabilities: BTreeMap<String, f64> =
                        q.options.iter().zip(&probs).map(|(o, p)| (o.name.clone(), *p)).collect();
                    let (choice, confidence) = probabilities
                        .iter()
                        .max_by(|a, b| a.1.total_cmp(b.1))
                        .map(|(k, v)| (k.clone(), *v))
                        .unwrap_or_default();
                    Answer::Choice { choice, confidence, probabilities }
                }
                QuestionType::Score => {
                    let (probs, total) = letter_probs(&resp, q.levels.len());
                    if total < 0.5 {
                        notes.push(format!("{}: low level mass {total:.2}", q.id));
                    }
                    Answer::Score {
                        score: probs.iter().enumerate().map(|(i, p)| i as f64 * p).sum(),
                        confidence: probs.iter().copied().fold(0.0, f64::max),
                        probabilities: probs.iter().enumerate().map(|(i, p)| (i.to_string(), *p)).collect(),
                    }
                }
            };
            answers.insert(q.id.clone(), answer);
        }
        Ok(Assessment { model, answers, notes, input_tokens: Some(input_tokens) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake Ollama reply whose first token has these top logprobs.
    fn reply(tokens: &[(&str, f64)]) -> Value {
        let top: Vec<Value> = tokens.iter().map(|(t, p)| json!({ "token": t, "logprob": p.ln() })).collect();
        json!({ "logprobs": [{ "top_logprobs": top }] })
    }

    #[test]
    fn letter_probs_sum_spellings_and_ignore_extra_letters() {
        // "B" and "B)" are the same answer; "D" is outside a 3-letter question.
        let (probs, total) = letter_probs(&reply(&[("B", 0.5), ("B)", 0.2), ("A", 0.1), ("D", 0.2)]), 3);
        assert!((total - 0.8).abs() < 1e-9);
        assert!((probs[0] - 0.125).abs() < 1e-9);
        assert!((probs[1] - 0.875).abs() < 1e-9);
        assert_eq!(probs[2], 0.0);
    }

    #[test]
    fn local_prompts_letter_every_option_and_level() {
        let c: AssessmentConfig = serde_saphyr::from_str(
            "questions:\n  - {id: s, type: score, instructions: How bad?, levels: [low, high]}\n  \
             - {id: c, type: choice, instructions: Who?, options: [{name: a, means: first}, {name: b}]}\n",
        )
        .unwrap();
        assert_eq!(
            Local::prompt(&c.questions[0]),
            "Question: How bad?\nLevels, lowest first:\nA) low\nB) high\nAnswer with the letter only."
        );
        assert_eq!(
            Local::prompt(&c.questions[1]),
            "Question: Who?\nOptions:\nA) a: first\nB) b\nAnswer with the letter only."
        );
    }
}
