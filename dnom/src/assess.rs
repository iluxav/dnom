//! Assessor (SPEC §4.4, §6, §7): asks the configured questions (`assessment:` in dnom.yaml)
//! about an episode, through one of three API shapes: System One (Jev and compatible
//! models), OpenAI Decisions, or a local Ollama model emulating typed answers.

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
    /// by level index ("0", "1", ...), as System One returns them.
    Score {
        score: f64,
        confidence: f64,
        probabilities: BTreeMap<String, f64>,
    },
}

#[derive(Debug)]
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
// System One API: Jev, Kev, Laya, Liquid d1, Cloudflare Clef
// ---------------------------------------------------------------------------------------------

pub struct SystemOne {
    name: String,
    agent: ureq::Agent,
    url: String,
    key: Option<String>,
    model: String,
    assessment: AssessmentConfig,
    /// `questions` object of the request, built once.
    questions_json: Value,
}

impl SystemOne {
    /// `model` overrides the backend's configured model.
    pub fn new(
        name: &str,
        def: &BackendDef,
        model: Option<&str>,
        assessment: AssessmentConfig,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            name: name.to_string(),
            agent: agent(Duration::from_secs(def.timeout_secs())),
            url: def.endpoint().with_context(|| format!("backend {name}"))?,
            key: def.api_key().with_context(|| format!("backend {name}"))?,
            model: model.unwrap_or(&def.model).to_string(),
            questions_json: Value::Object(
                assessment.questions.iter().map(|q| (q.id.clone(), q.to_jev())).collect(),
            ),
            assessment,
        })
    }
}

/// Answers from a System One response. Cloudflare's REST API wraps the body in
/// `{"result": ..., "success": true}`; that wrapper is removed first.
fn parse_systemone(questions: &[Question], resp: &Value, fallback_model: &str) -> anyhow::Result<Assessment> {
    let body = if resp.get("answers").is_none() && resp["result"].get("answers").is_some() {
        &resp["result"]
    } else {
        resp
    };
    let mut answers = BTreeMap::new();
    for q in questions {
        answers.insert(q.id.clone(), parse_systemone_answer(q, &body["answers"][&q.id])?);
    }
    Ok(Assessment {
        model: body["model"].as_str().unwrap_or(fallback_model).to_string(),
        answers,
        notes: Vec::new(),
        input_tokens: body["usage"]["input_tokens"].as_u64(),
    })
}

/// Reads one System One answer, checking its type matches the question.
fn parse_systemone_answer(q: &Question, a: &Value) -> anyhow::Result<Answer> {
    let num = |field: &str| a[field].as_f64().ok_or_else(|| anyhow!("answer '{}' has no {field}", q.id));
    let probabilities =
        || -> BTreeMap<String, f64> { serde_json::from_value(a["probabilities"].clone()).unwrap_or_default() };
    Ok(match q.kind {
        QuestionType::Noul => Answer::Noul { noul: num("noul")? },
        QuestionType::Choice => Answer::Choice {
            choice: a["choice"]
                .as_str()
                .ok_or_else(|| anyhow!("answer '{}' has no choice", q.id))?
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

impl Backend for SystemOne {
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
        parse_systemone(&self.assessment.questions, &resp, &self.model)
    }
}

// ---------------------------------------------------------------------------------------------
// OpenAI Decisions API (developers.openai.com/api/docs/guides/decisions)
// ---------------------------------------------------------------------------------------------

pub struct OpenAi {
    name: String,
    agent: ureq::Agent,
    url: String,
    key: Option<String>,
    model: String,
    assessment: AssessmentConfig,
}

impl OpenAi {
    pub fn new(
        name: &str,
        def: &BackendDef,
        model: Option<&str>,
        assessment: AssessmentConfig,
    ) -> anyhow::Result<Self> {
        for q in &assessment.questions {
            ensure!(
                q.kind != QuestionType::Score || q.levels.len() >= 2,
                "backend {name}: OpenAI score questions need at least 2 levels ('{}' has {})",
                q.id,
                q.levels.len()
            );
        }
        Ok(Self {
            name: name.to_string(),
            agent: agent(Duration::from_secs(def.timeout_secs())),
            url: def.endpoint().with_context(|| format!("backend {name}"))?,
            key: def.api_key().with_context(|| format!("backend {name}"))?,
            model: model.unwrap_or(&def.model).to_string(),
            assessment,
        })
    }
}

/// Request body: the context as a developer message, the episode as JSON data, and the
/// questions translated (noul -> predicate, with its yes/no meanings in the instructions).
fn openai_request(model: &str, assessment: &AssessmentConfig, episode: &Value) -> Value {
    let questions: Vec<Value> = assessment
        .questions
        .iter()
        .map(|q| match q.kind {
            QuestionType::Noul => json!({
                "type": "predicate",
                "name": q.id,
                "instructions": format!(
                    "{}\nTrue means: {}\nFalse means: {}",
                    q.instructions,
                    q.yes_means.as_deref().unwrap_or(""),
                    q.no_means.as_deref().unwrap_or(""),
                ),
            }),
            QuestionType::Choice => json!({
                "type": "choice",
                "name": q.id,
                "instructions": q.instructions,
                "choices": q.options.iter().map(|o| json!({
                    "value": o.name,
                    "description": o.means.as_deref().unwrap_or(&o.name),
                })).collect::<Vec<_>>(),
            }),
            QuestionType::Score => json!({
                "type": "score",
                "name": q.id,
                "instructions": q.instructions,
                "levels": q.levels.iter().map(|l| json!({ "label": l, "description": l })).collect::<Vec<_>>(),
            }),
        })
        .collect();
    json!({
        "model": model,
        "input": [
            { "role": "developer", "content": [{ "type": "input_text", "text": assessment.context }] },
            { "role": "user", "content": [{ "type": "input_json", "data": episode }] },
        ],
        "questions": questions,
    })
}

/// Answers from an OpenAI Decisions response (an `answers` list matched by `name`).
/// A refused question gets no answer and a note; policies treat it as unknown.
fn parse_openai(questions: &[Question], resp: &Value, fallback_model: &str) -> anyhow::Result<Assessment> {
    let list = resp["answers"].as_array().ok_or_else(|| anyhow!("openai: response has no answers list"))?;
    let by_name: BTreeMap<&str, &Value> =
        list.iter().filter_map(|a| Some((a["name"].as_str()?, a))).collect();
    let mut answers = BTreeMap::new();
    let mut notes = Vec::new();
    for q in questions {
        let a = by_name.get(q.id.as_str()).ok_or_else(|| anyhow!("openai: no answer for '{}'", q.id))?;
        if a["type"] == "refusal" {
            notes.push(format!("{}: refused", q.id));
            continue;
        }
        let num = |v: &Value, field: &str| v[field].as_f64().ok_or_else(|| anyhow!("openai: '{}' has no {field}", q.id));
        let answer = match q.kind {
            QuestionType::Noul => Answer::Noul { noul: num(a, "probability")? },
            QuestionType::Choice => Answer::Choice {
                choice: a["choice"].as_str().ok_or_else(|| anyhow!("openai: '{}' has no choice", q.id))?.to_string(),
                confidence: a["confidence"].as_f64().unwrap_or(0.0),
                probabilities: a["probabilities"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|p| Some((p["value"].as_str()?.to_string(), p["probability"].as_f64()?)))
                    .collect(),
            },
            QuestionType::Score => Answer::Score {
                score: num(a, "score")?,
                confidence: a["confidence"].as_f64().unwrap_or(0.0),
                // Keyed by level index, like System One.
                probabilities: a["probabilities"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|p| Some((p["value"].as_u64()?.to_string(), p["probability"].as_f64()?)))
                    .collect(),
            },
        };
        answers.insert(q.id.clone(), answer);
    }
    Ok(Assessment {
        model: resp["model"].as_str().unwrap_or(fallback_model).to_string(),
        answers,
        notes,
        input_tokens: resp["usage"]["input_tokens"].as_u64(),
    })
}

impl Backend for OpenAi {
    fn name(&self) -> &str {
        &self.name
    }

    fn assess(&self, episode: &Value) -> anyhow::Result<Assessment> {
        let body = openai_request(&self.model, &self.assessment, episode);
        let resp = post_json(&self.agent, &self.url, self.key.as_deref(), &body)?;
        parse_openai(&self.assessment.questions, &resp, &self.model)
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
            url: def.endpoint().with_context(|| format!("backend {name}"))?,
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

    fn three_questions() -> AssessmentConfig {
        serde_saphyr::from_str(
            "questions:\n  \
             - {id: risky, type: noul, instructions: Is it risky?, yes_means: risky, no_means: fine}\n  \
             - {id: team, type: choice, instructions: Which team?, options: [{name: secops, means: Security}, {name: it}]}\n  \
             - {id: severity, type: score, instructions: How bad?, levels: [low, medium, high]}\n",
        )
        .unwrap()
    }

    #[test]
    fn systemone_plain_and_cloudflare_wrapped() {
        let a = three_questions();
        let body = json!({
            "model": "clef",
            "answers": {
                "risky": { "type": "noul", "noul": 0.9 },
                "team": { "type": "choice", "choice": "secops", "confidence": 0.8, "probabilities": { "secops": 0.85, "it": 0.15 } },
                "severity": { "type": "score", "score": 1.7, "confidence": 0.55, "probabilities": { "0": 0.1, "1": 0.1, "2": 0.8 } },
            },
            "usage": { "input_tokens": 321 },
        });
        for resp in [body.clone(), json!({ "result": body, "success": true, "errors": [], "messages": [] })] {
            let got = parse_systemone(&a.questions, &resp, "fallback").unwrap();
            assert_eq!((got.model.as_str(), got.input_tokens), ("clef", Some(321)));
            assert!(matches!(got.answers["risky"], Answer::Noul { noul } if noul == 0.9));
            assert!(matches!(&got.answers["team"], Answer::Choice { choice, .. } if choice == "secops"));
            assert!(matches!(got.answers["severity"], Answer::Score { score, .. } if score == 1.7));
        }
    }

    #[test]
    fn openai_request_translates_question_types() {
        let req = openai_request("gpt-6-luna", &three_questions(), &json!({ "episode_id": "ep-1" }));
        assert_eq!(req["model"], "gpt-6-luna");
        assert_eq!(req["input"][1]["content"][0], json!({ "type": "input_json", "data": { "episode_id": "ep-1" } }));
        let q = &req["questions"];
        assert_eq!(q[0]["type"], "predicate");
        assert_eq!(q[0]["instructions"], "Is it risky?\nTrue means: risky\nFalse means: fine");
        assert_eq!(q[1]["choices"], json!([{ "value": "secops", "description": "Security" }, { "value": "it", "description": "it" }]));
        assert_eq!(q[2]["levels"][2], json!({ "label": "high", "description": "high" }));
    }

    #[test]
    fn openai_response_with_a_refusal() {
        let a = three_questions();
        // Shapes from the OpenAI Decisions guide.
        let resp = json!({
            "answers": [
                { "type": "predicate", "name": "risky", "probability": 0.92 },
                { "type": "choice", "name": "team", "choice": "secops", "confidence": 0.93,
                  "probabilities": [{ "value": "secops", "probability": 0.95 }, { "value": "it", "probability": 0.05 }] },
                { "type": "refusal", "name": "severity" },
            ],
            "usage": { "input_tokens": 512 },
        });
        let got = parse_openai(&a.questions, &resp, "gpt-6-luna").unwrap();
        assert!(matches!(got.answers["risky"], Answer::Noul { noul } if noul == 0.92));
        let Answer::Choice { probabilities, .. } = &got.answers["team"] else { panic!() };
        assert_eq!(probabilities["secops"], 0.95);
        // Refused: no answer (policies see it as unknown), plus a note.
        assert!(!got.answers.contains_key("severity"));
        assert_eq!(got.notes, ["severity: refused"]);
        assert_eq!((got.model.as_str(), got.input_tokens), ("gpt-6-luna", Some(512)));
        // A missing answer (not a refusal) is an error.
        let partial = json!({ "answers": [{ "type": "predicate", "name": "risky", "probability": 0.5 }] });
        assert!(parse_openai(&a.questions, &partial, "m").unwrap_err().to_string().contains("no answer for 'team'"));
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
