use super::ir::{
    CanonicalContentBlock, CanonicalMessage, CanonicalRequest, CanonicalStreamEvent, CanonicalTool,
    ThinkingConfig, clamp_tool_call_id,
};
use anyhow::Result;
use serde_json::{Value, json};

pub fn decode_request(body: &Value) -> Result<CanonicalRequest> {
    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut system = Vec::new();
    if let Some(s) = body.get("system").and_then(Value::as_str) {
        system.push(s.to_string());
    } else if let Some(arr) = body.get("system").and_then(Value::as_array) {
        for item in arr {
            if let Some(t) = item.get("text").and_then(Value::as_str) {
                system.push(t.to_string());
            }
        }
    }

    let mut messages = Vec::new();
    if let Some(arr) = body.get("messages").and_then(Value::as_array) {
        for m in arr {
            let role = m
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("user")
                .to_string();
            let mut blocks = Vec::new();
            if let Some(s) = m.get("content").and_then(Value::as_str) {
                blocks.push(CanonicalContentBlock::Text {
                    text: s.to_string(),
                });
            } else if let Some(parts) = m.get("content").and_then(Value::as_array) {
                for p in parts {
                    match p.get("type").and_then(Value::as_str) {
                        Some("text") => {
                            if let Some(t) = p.get("text").and_then(Value::as_str) {
                                blocks.push(CanonicalContentBlock::Text {
                                    text: t.to_string(),
                                });
                            }
                        }
                        Some("image") => {
                            if let Some(src) = p.get("source")
                                && let (Some(mt), Some(data)) = (
                                    src.get("media_type").and_then(Value::as_str),
                                    src.get("data").and_then(Value::as_str),
                                )
                            {
                                blocks.push(CanonicalContentBlock::ImageBase64 {
                                    media_type: mt.to_string(),
                                    data: data.to_string(),
                                });
                            }
                        }
                        Some("tool_use") => {
                            let id = clamp_tool_call_id(
                                p.get("id").and_then(Value::as_str).unwrap_or("tc_0"),
                            );
                            let name = p
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string();
                            let input = p.get("input").cloned().unwrap_or_else(|| json!({}));
                            blocks.push(CanonicalContentBlock::ToolUse { id, name, input });
                        }
                        Some("tool_result") => {
                            let tool_use_id = clamp_tool_call_id(
                                p.get("tool_use_id")
                                    .and_then(Value::as_str)
                                    .unwrap_or("tc_0"),
                            );
                            let is_error = p
                                .get("is_error")
                                .and_then(Value::as_bool)
                                .unwrap_or(false);
                            let content = if let Some(s) = p.get("content").and_then(Value::as_str)
                            {
                                s.to_string()
                            } else {
                                p.get("content")
                                    .map(|v| v.to_string())
                                    .unwrap_or_default()
                            };
                            blocks.push(CanonicalContentBlock::ToolResult {
                                tool_use_id,
                                content,
                                is_error,
                            });
                        }
                        _ => {}
                    }
                }
            }
            messages.push(CanonicalMessage {
                role,
                content: blocks,
            });
        }
    }

    let mut tools = Vec::new();
    if let Some(arr) = body.get("tools").and_then(Value::as_array) {
        for t in arr {
            if let Some(name) = t.get("name").and_then(Value::as_str) {
                tools.push(CanonicalTool {
                    name: name.to_string(),
                    description: t
                        .get("description")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    input_schema: t
                        .get("input_schema")
                        .cloned()
                        .unwrap_or_else(|| json!({"type": "object", "properties": {}})),
                });
            }
        }
    }

    let thinking = body.get("thinking").and_then(|th| {
        if th.get("type").and_then(Value::as_str) == Some("enabled") {
            Some(ThinkingConfig {
                budget_tokens: th.get("budget_tokens").and_then(Value::as_u64),
                effort: None,
            })
        } else {
            None
        }
    });

    Ok(CanonicalRequest {
        model,
        system,
        messages,
        tools,
        tool_choice: body.get("tool_choice").cloned(),
        max_tokens: body.get("max_tokens").and_then(Value::as_u64),
        temperature: body.get("temperature").and_then(Value::as_f64),
        stream: body.get("stream").and_then(Value::as_bool).unwrap_or(false),
        thinking,
    })
}

pub fn encode_request(req: &CanonicalRequest) -> Value {
    let mut messages = Vec::new();
    for msg in &req.messages {
        let content: Vec<Value> = msg
            .content
            .iter()
            .map(|b| match b {
                CanonicalContentBlock::Text { text } => json!({ "type": "text", "text": text }),
                CanonicalContentBlock::ImageBase64 { media_type, data } => json!({
                    "type": "image",
                    "source": { "type": "base64", "media_type": media_type, "data": data }
                }),
                CanonicalContentBlock::ToolUse { id, name, input } => json!({
                    "type": "tool_use",
                    "id": clamp_tool_call_id(id),
                    "name": name,
                    "input": input
                }),
                CanonicalContentBlock::ToolResult {
                    tool_use_id,
                    content,
                    is_error,
                } => json!({
                    "type": "tool_result",
                    "tool_use_id": clamp_tool_call_id(tool_use_id),
                    "content": content,
                    "is_error": is_error
                }),
            })
            .collect();
        messages.push(json!({ "role": msg.role, "content": content }));
    }

    let mut out = json!({
        "model": req.model,
        "max_tokens": req.max_tokens.unwrap_or(4096),
        "messages": messages,
        "stream": req.stream,
    });
    if !req.system.is_empty() {
        out["system"] = json!(req.system.join("\n\n"));
    }
    if let Some(temp) = req.temperature {
        out["temperature"] = json!(temp);
    }
    if !req.tools.is_empty() {
        out["tools"] = Value::Array(
            req.tools
                .iter()
                .map(|t| {
                    json!({
                        "name": t.name,
                        "description": t.description.as_deref().unwrap_or(""),
                        "input_schema": t.input_schema,
                    })
                })
                .collect(),
        );
    }
    if let Some(ref th) = req.thinking {
        out["thinking"] = json!({
            "type": "enabled",
            "budget_tokens": th.to_budget_tokens()
        });
    }
    out
}

pub fn decode_sse_chunk(event_type: Option<&str>, data: &str) -> Vec<CanonicalStreamEvent> {
    let Ok(v) = serde_json::from_str::<Value>(data.trim()) else {
        return Vec::new();
    };
    let kind = event_type
        .or_else(|| v.get("type").and_then(Value::as_str))
        .unwrap_or("");
    let mut out = Vec::new();
    match kind {
        "content_block_start" => {
            if let Some(cb) = v.get("content_block")
                && cb.get("type").and_then(Value::as_str) == Some("tool_use")
            {
                let index = v.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                let id = clamp_tool_call_id(cb.get("id").and_then(Value::as_str).unwrap_or("tc_0"));
                let name = cb
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                out.push(CanonicalStreamEvent::ToolCallStart { index, id, name });
            }
        }
        "content_block_delta" => {
            let index = v.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
            if let Some(delta) = v.get("delta") {
                match delta.get("type").and_then(Value::as_str) {
                    Some("text_delta") => {
                        if let Some(t) = delta.get("text").and_then(Value::as_str) {
                            out.push(CanonicalStreamEvent::TextDelta(t.to_string()));
                        }
                    }
                    Some("thinking_delta") => {
                        if let Some(t) = delta.get("thinking").and_then(Value::as_str) {
                            out.push(CanonicalStreamEvent::ReasoningDelta(t.to_string()));
                        }
                    }
                    Some("input_json_delta") => {
                        if let Some(p) = delta.get("partial_json").and_then(Value::as_str) {
                            out.push(CanonicalStreamEvent::ToolCallArgsDelta {
                                index,
                                delta: p.to_string(),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
        "message_delta" => {
            if let Some(u) = v.get("usage") {
                let input_tokens = u.get("input_tokens").and_then(Value::as_u64).unwrap_or(0);
                let output_tokens = u.get("output_tokens").and_then(Value::as_u64).unwrap_or(0);
                out.push(CanonicalStreamEvent::Usage {
                    input_tokens,
                    output_tokens,
                });
            }
            if let Some(reason) = v
                .get("delta")
                .and_then(|d| d.get("stop_reason"))
                .and_then(Value::as_str)
            {
                out.push(CanonicalStreamEvent::Finish {
                    reason: reason.to_string(),
                });
            }
        }
        _ => {}
    }
    out
}

pub fn encode_sse_event(ev: &CanonicalStreamEvent, _model: &str) -> Vec<String> {
    match ev {
        CanonicalStreamEvent::TextDelta(t) => vec![format!(
            "event: content_block_delta\ndata: {}\n\n",
            json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": t } })
        )],
        CanonicalStreamEvent::ReasoningDelta(r) => vec![format!(
            "event: content_block_delta\ndata: {}\n\n",
            json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "thinking_delta", "thinking": r } })
        )],
        CanonicalStreamEvent::ToolCallStart { index, id, name } => vec![format!(
            "event: content_block_start\ndata: {}\n\n",
            json!({
                "type": "content_block_start",
                "index": index,
                "content_block": { "type": "tool_use", "id": clamp_tool_call_id(id), "name": name, "input": {} }
            })
        )],
        CanonicalStreamEvent::ToolCallArgsDelta { index, delta } => vec![format!(
            "event: content_block_delta\ndata: {}\n\n",
            json!({
                "type": "content_block_delta",
                "index": index,
                "delta": { "type": "input_json_delta", "partial_json": delta }
            })
        )],
        CanonicalStreamEvent::ToolCallEnd { index } => vec![format!(
            "event: content_block_stop\ndata: {}\n\n",
            json!({ "type": "content_block_stop", "index": index })
        )],
        CanonicalStreamEvent::Usage {
            input_tokens,
            output_tokens,
        } => vec![format!(
            "event: message_delta\ndata: {}\n\n",
            json!({ "type": "message_delta", "delta": {}, "usage": { "input_tokens": input_tokens, "output_tokens": output_tokens } })
        )],
        CanonicalStreamEvent::Finish { reason } => vec![
            format!(
                "event: message_delta\ndata: {}\n\n",
                json!({ "type": "message_delta", "delta": { "stop_reason": reason } })
            ),
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_string(),
        ],
        CanonicalStreamEvent::Error { message } => vec![format!(
            "event: error\ndata: {}\n\n",
            json!({ "type": "error", "error": { "type": "api_error", "message": message } })
        )],
    }
}
