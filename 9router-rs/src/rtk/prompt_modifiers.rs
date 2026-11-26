use crate::config::schema::RtkConfig;
use serde_json::{Value, json};

pub fn caveman_prompt(level: &str) -> Option<&'static str> {
    match level {
        "lite" => Some(
            "Respond concisely. Skip filler and greetings. Keep all technical details and code intact.",
        ),
        "full" => Some(
            "Respond tersely like a senior engineer: short fragments, drop articles/filler, keep code and error details exact.",
        ),
        "ultra" => Some(
            "Ultra-terse mode: minimal words, bullet fragments only, zero prose padding; preserve code, paths, and identifiers verbatim.",
        ),
        _ => None,
    }
}

pub fn ponytail_prompt(level: &str) -> Option<&'static str> {
    match level {
        "lite" => Some(
            "Write minimal, direct code. Avoid speculative abstractions and unnecessary comments while preserving validation and error handling.",
        ),
        "full" => Some(
            "Keep changes strictly scoped to the request. Avoid extra helper wrappers, redundant boilerplate, and unrequested refactors; preserve safety and validation.",
        ),
        "ultra" => Some(
            "Emit the smallest correct implementation possible. Zero boilerplate, zero dead code, preserve security, error handling, and explicit requirements.",
        ),
        _ => None,
    }
}

/// Appends Caveman, 3-level Ponytail, and Custom Prompt modifiers to system instructions
/// without mutating OpenCode `<env>` blocks or tool definitions.
pub fn apply_prompt_modifiers(body: &mut Value, cfg: &RtkConfig) {
    let mut additions: Vec<&str> = Vec::new();
    if let Some(p) = caveman_prompt(&cfg.caveman_level) {
        additions.push(p);
    }
    if let Some(p) = ponytail_prompt(&cfg.ponytail_level) {
        additions.push(p);
    }
    let custom = cfg.custom_prompt.trim();
    if !custom.is_empty() {
        additions.push(custom);
    }
    if additions.is_empty() {
        return;
    }

    let suffix = additions.join("\n\n");
    inject_system_prompt(body, &suffix);
}

pub fn inject_system_prompt(body: &mut Value, addition: &str) {
    // 1. Anthropic Messages format: top-level `system` (string or array of text blocks)
    if let Some(sys) = body.get_mut("system") {
        if let Some(s) = sys.as_str() {
            *sys = Value::String(format!("{s}\n\n{addition}"));
            return;
        }
        if let Some(arr) = sys.as_array_mut() {
            arr.push(json!({ "type": "text", "text": addition }));
            return;
        }
    }

    // 2. OpenAI Responses format: top-level `instructions`
    if body.get("input").is_some() {
        if let Some(inst) = body.get("instructions").and_then(Value::as_str).map(ToOwned::to_owned) {
            body["instructions"] = Value::String(format!("{inst}\n\n{addition}"));
        } else {
            body["instructions"] = Value::String(addition.to_string());
        }
        return;
    }

    // 3. OpenAI Chat format: messages[] with system/developer role
    if let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) {
        if let Some(first) = messages.first_mut()
            && matches!(
                first.get("role").and_then(Value::as_str),
                Some("system" | "developer")
            )
            && let Some(content) = first.get("content").and_then(Value::as_str)
        {
            first["content"] = Value::String(format!("{content}\n\n{addition}"));
            return;
        }
        messages.insert(0, json!({ "role": "system", "content": addition }));
    }
}
