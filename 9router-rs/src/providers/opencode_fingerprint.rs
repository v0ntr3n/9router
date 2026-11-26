use crate::config::schema::OpenCodeProfile;
use lru::LruCache;
use rand::RngCore;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;

pub const MAX_TRANSLATED_SESSIONS: usize = 5000;
const BASE62_CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const SESSION_PREFIX_MASK: u64 = (1u64 << 48) - 1;

#[derive(Debug, Default, Clone)]
pub struct FingerprintReport {
    pub session_id: String,
    pub env_marker_present: bool,
    pub tools_appended: Vec<String>,
    pub aliased_tools: HashMap<String, String>, // upstream_alias -> caller_original
}

pub struct OpenCodeSessionStore {
    lru: Mutex<LruCache<String, String>>,
}

impl OpenCodeSessionStore {
    pub fn new(cap: usize) -> Self {
        let cap = NonZeroUsize::new(cap.max(1)).unwrap();
        Self {
            lru: Mutex::new(LruCache::new(cap)),
        }
    }

    pub fn generate_session_id(now_ms: u64, counter: u64) -> String {
        let descending = (!(now_ms.wrapping_mul(0x1000).wrapping_add(counter))) & SESSION_PREFIX_MASK;
        let mut rand_bytes = [0u8; 14];
        rand::thread_rng().fill_bytes(&mut rand_bytes);
        let mut suffix = String::with_capacity(14);
        for b in rand_bytes {
            suffix.push(BASE62_CHARS[(b as usize) % 62] as char);
        }
        format!("ses_{descending:012x}{suffix}")
    }

    pub fn get_or_mint(&self, caller_key: &str) -> String {
        let mut guard = self.lru.lock().unwrap();
        if let Some(existing) = guard.get(caller_key) {
            return existing.clone();
        }
        let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
        let minted = Self::generate_session_id(now_ms, 1);
        guard.put(caller_key.to_string(), minted.clone());
        minted
    }

    /// Value-matched invalidation on 403 / non-overload 429 so newer concurrent sessions are not evicted.
    pub fn invalidate_if_matches(&self, caller_key: &str, expected_session_id: &str) -> bool {
        let mut guard = self.lru.lock().unwrap();
        if guard.peek(caller_key).map(String::as_str) == Some(expected_session_id) {
            guard.pop(caller_key);
            return true;
        }
        false
    }

    pub fn clear_all(&self) {
        if let Ok(mut guard) = self.lru.lock() {
            guard.clear();
        }
    }

    pub fn len(&self) -> usize {
        self.lru.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Applies OpenCode free-tier request fingerprinting:
/// - `<env>` marker check
/// - `concealFingerprintToolNames` (`read`/`shell` collisions -> `read_client`/`shell_client`, `/terminal/i` -> `run_command`)
/// - `retargetToolChoice` & `aliasHistoryToolCalls`
/// - `appendMissingFingerprintTools` (`read`, `shell`) + `noteUnavailableTools`
/// - `tool_choice = "auto"` when unset on Responses payloads
/// - forced `stream: true`
pub fn apply_opencode_fingerprint(
    body: &mut Value,
    profile: &OpenCodeProfile,
    session_id: String,
) -> FingerprintReport {
    let mut report = FingerprintReport {
        session_id,
        ..Default::default()
    };

    // Force stream: true as required by OpenCode free gate
    body["stream"] = Value::Bool(true);

    let mut forward_map: HashMap<String, String> = HashMap::new(); // caller_original -> upstream_alias

    // 1. Conceal colliding tool names (`read`, `shell`, or `/terminal/i`)
    if let Some(tools) = body.get_mut("tools").and_then(Value::as_array_mut) {
        for tool in tools.iter_mut() {
            let name_slot = if tool.get("function").is_some() {
                tool.pointer_mut("/function/name")
            } else {
                tool.get_mut("name")
            };
            if let Some(name_val) = name_slot
                && let Some(orig) = name_val.as_str().map(ToOwned::to_owned)
            {
                let alias = if orig.eq_ignore_ascii_case("read") {
                    Some("read_client".to_string())
                } else if orig.eq_ignore_ascii_case("shell") {
                    Some("shell_client".to_string())
                } else if orig.to_ascii_lowercase().contains("terminal") {
                    Some("run_command".to_string())
                } else {
                    None
                };
                if let Some(aliased) = alias {
                    *name_val = Value::String(aliased.clone());
                    forward_map.insert(orig.clone(), aliased.clone());
                    report.aliased_tools.insert(aliased, orig);
                }
            }
        }
    }

    // 2. Retarget tool_choice if it references an aliased tool
    if let Some(tc) = body.get_mut("tool_choice") {
        if let Some(name) = tc
            .pointer("/function/name")
            .or_else(|| tc.get("name"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            && let Some(aliased) = forward_map.get(&name)
        {
            if let Some(slot) = tc.pointer_mut("/function/name") {
                *slot = Value::String(aliased.clone());
            } else if let Some(slot) = tc.get_mut("name") {
                *slot = Value::String(aliased.clone());
            }
        }
    } else if body.get("input").is_some() {
        body["tool_choice"] = Value::String("auto".to_string());
    }

    // 3. Alias history tool calls so prior turns match the concealed tool schema
    if !forward_map.is_empty() {
        alias_history_tool_calls(body, &forward_map);
    }

    // 4. Append missing fingerprint tools (`read`, `shell`) + noteUnavailableTools
    let is_openai_chat = body.get("messages").is_some() && body.get("max_tokens").is_none();
    let mut has_read = false;
    let mut has_shell = false;
    if let Some(tools) = body.get("tools").and_then(Value::as_array) {
        for t in tools {
            let n = t
                .pointer("/function/name")
                .or_else(|| t.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if n == "read" {
                has_read = true;
            }
            if n == "shell" {
                has_shell = true;
            }
        }
    }

    if body.get("tools").is_none() {
        body["tools"] = Value::Array(Vec::new());
    }
    if let Some(tools) = body.get_mut("tools").and_then(Value::as_array_mut) {
        if !has_read {
            tools.push(fingerprint_tool_def("read", is_openai_chat));
            report.tools_appended.push("read".to_string());
        }
        if !has_shell {
            tools.push(fingerprint_tool_def("shell", is_openai_chat));
            report.tools_appended.push("shell".to_string());
        }
    }

    // Check `<env>` marker presence and append noteUnavailableTools if placeholders were injected
    let serialized = body.to_string();
    report.env_marker_present = serialized.contains(&profile.env_marker);
    if !report.tools_appended.is_empty() {
        let notice = format!(
            "Note: Placeholder tools ({}) are unavailable in this environment; do not invoke them.",
            report.tools_appended.join(", ")
        );
        crate::rtk::prompt_modifiers::inject_system_prompt(body, &notice);
    }

    report
}

fn fingerprint_tool_def(name: &str, openai_chat_shape: bool) -> Value {
    let schema = match name {
        "read" => json!({
            "type": "object",
            "properties": { "filePath": { "type": "string" } },
            "required": ["filePath"]
        }),
        _ => json!({
            "type": "object",
            "properties": { "command": { "type": "string" } },
            "required": ["command"]
        }),
    };
    if openai_chat_shape {
        json!({
            "type": "function",
            "function": {
                "name": name,
                "description": format!("OpenCode {name} tool"),
                "parameters": schema
            }
        })
    } else {
        json!({
            "type": "function",
            "name": name,
            "description": format!("OpenCode {name} tool"),
            "parameters": schema
        })
    }
}

fn alias_history_tool_calls(body: &mut Value, forward_map: &HashMap<String, String>) {
    if let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) {
        for msg in messages.iter_mut() {
            if let Some(tcs) = msg.get_mut("tool_calls").and_then(Value::as_array_mut) {
                for tc in tcs.iter_mut() {
                    if let Some(name_slot) = tc.pointer_mut("/function/name")
                        && let Some(orig) = name_slot.as_str()
                        && let Some(aliased) = forward_map.get(orig)
                    {
                        *name_slot = Value::String(aliased.clone());
                    }
                }
            }
            if let Some(parts) = msg.get_mut("content").and_then(Value::as_array_mut) {
                for p in parts.iter_mut() {
                    if p.get("type").and_then(Value::as_str) == Some("tool_use")
                        && let Some(name_slot) = p.get_mut("name")
                        && let Some(orig) = name_slot.as_str()
                        && let Some(aliased) = forward_map.get(orig)
                    {
                        *name_slot = Value::String(aliased.clone());
                    }
                }
            }
        }
    }
    if let Some(input) = body.get_mut("input").and_then(Value::as_array_mut) {
        for item in input.iter_mut() {
            if item.get("type").and_then(Value::as_str) == Some("function_call")
                && let Some(name_slot) = item.get_mut("name")
                && let Some(orig) = name_slot.as_str()
                && let Some(aliased) = forward_map.get(orig)
            {
                *name_slot = Value::String(aliased.clone());
            }
        }
    }
}

/// Restores aliased tool names (`read_client`, `shell_client`, `run_command`) back to caller names
/// in SSE chunks or aggregated JSON responses.
pub fn restore_tool_names_in_text(chunk: &str, aliased_to_orig: &HashMap<String, String>) -> String {
    if aliased_to_orig.is_empty() {
        return chunk.to_string();
    }
    let mut out = chunk.to_string();
    for (alias, orig) in aliased_to_orig {
        let needle = format!("\"name\":\"{alias}\"");
        let replacement = format!("\"name\":\"{orig}\"");
        out = out.replace(&needle, &replacement);
        let needle_spaced = format!("\"name\": \"{alias}\"");
        let replacement_spaced = format!("\"name\": \"{orig}\"");
        out = out.replace(&needle_spaced, &replacement_spaced);
    }
    out
}
