pub mod autodetect;
pub mod filters;
pub mod prompt_modifiers;

use crate::config::schema::RtkConfig;
use serde_json::Value;

pub const MIN_COMPRESS_SIZE: usize = 500;
pub const RAW_CAP: usize = 10 * 1024 * 1024;
pub const DETECT_WINDOW: usize = 1024;

#[derive(Debug, Default, Clone)]
pub struct RtkOutcome {
    pub compressed_blocks: usize,
    pub bytes_saved: usize,
    pub tokens_saved_est: u64,
}

/// Applies fail-open RTK tool_result compression + prompt modifiers BEFORE translation and OpenCode fingerprinting.
pub fn apply_pre_translate(body: &mut Value, cfg: &RtkConfig, bypass_header: bool) -> RtkOutcome {
    if bypass_header {
        return RtkOutcome::default();
    }

    let mut outcome = RtkOutcome::default();
    if cfg.enabled {
        compress_tool_results(body, &mut outcome);
    }

    prompt_modifiers::apply_prompt_modifiers(body, cfg);
    outcome.tokens_saved_est = (outcome.bytes_saved / 4) as u64;
    outcome
}

fn compress_text_fail_open(input: &str) -> Option<String> {
    if input.len() < MIN_COMPRESS_SIZE || input.len() > RAW_CAP {
        return None;
    }
    let filter_name = autodetect::detect_filter(input)?;
    let result = std::panic::catch_unwind(|| filters::run_filter(filter_name, input)).ok()??;
    if result.len() < input.len() {
        Some(result)
    } else {
        None
    }
}

fn compress_tool_results(body: &mut Value, outcome: &mut RtkOutcome) {
    // 1. OpenAI Chat & Anthropic Messages: body.messages[]
    if let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) {
        for msg in messages.iter_mut() {
            let role = msg.get("role").and_then(Value::as_str).unwrap_or("");
            // OpenAI tool role message
            if role == "tool" {
                if let Some(content) = msg.get("content").and_then(Value::as_str)
                    && let Some(compressed) = compress_text_fail_open(content)
                {
                    outcome.bytes_saved += content.len() - compressed.len();
                    outcome.compressed_blocks += 1;
                    msg["content"] = Value::String(compressed);
                }
                continue;
            }
            // Anthropic tool_result blocks inside user message content[]
            if let Some(parts) = msg.get_mut("content").and_then(Value::as_array_mut) {
                for part in parts.iter_mut() {
                    if part.get("type").and_then(Value::as_str) != Some("tool_result") {
                        continue;
                    }
                    if part.get("is_error").and_then(Value::as_bool) == Some(true) {
                        continue;
                    }
                    if let Some(text) = part.get("content").and_then(Value::as_str) {
                        if let Some(compressed) = compress_text_fail_open(text) {
                            outcome.bytes_saved += text.len() - compressed.len();
                            outcome.compressed_blocks += 1;
                            part["content"] = Value::String(compressed);
                        }
                    } else if let Some(blocks) =
                        part.get_mut("content").and_then(Value::as_array_mut)
                    {
                        for b in blocks.iter_mut() {
                            if b.get("type").and_then(Value::as_str) == Some("text")
                                && let Some(text) = b.get("text").and_then(Value::as_str)
                                && let Some(compressed) = compress_text_fail_open(text)
                            {
                                outcome.bytes_saved += text.len() - compressed.len();
                                outcome.compressed_blocks += 1;
                                b["text"] = Value::String(compressed);
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. OpenAI Responses: body.input[] function_call_output items
    if let Some(input) = body.get_mut("input").and_then(Value::as_array_mut) {
        for item in input.iter_mut() {
            if item.get("type").and_then(Value::as_str) != Some("function_call_output") {
                continue;
            }
            if let Some(text) = item.get("output").and_then(Value::as_str)
                && let Some(compressed) = compress_text_fail_open(text)
            {
                outcome.bytes_saved += text.len() - compressed.len();
                outcome.compressed_blocks += 1;
                item["output"] = Value::String(compressed);
            }
        }
    }
}
