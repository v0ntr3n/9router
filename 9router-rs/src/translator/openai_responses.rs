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
    if let Some(inst) = body.get("instructions").and_then(Value::as_str)
        && !inst.is_empty()
    {
        system.push(inst.to_string());
    }

    let mut messages = Vec::new();
    if let Some(s) = body.get("input").and_then(Value::as_str) {
        messages.push(CanonicalMessage {
            role: "user".to_string(),
            content: vec![CanonicalContentBlock::Text {
                text: s.to_string(),
            }],
        });
    } else if let Some(items) = body.get("input").and_then(Value::as_array) {
        for item in items {
            match item.get("type").and_then(Value::as_str) {
                Some("function_call") => {
                    let id = clamp_tool_call_id(
                        item.get("call_id")
                            .or_else(|| item.get("id"))
                            .and_then(Value::as_str)
                            .unwrap_or("tc_0"),
                    );
                    let name = item
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let args = item
                        .get("arguments")
                        .and_then(Value::as_str)
                        .unwrap_or("{}");
                    let input: Value = serde_json::from_str(args).unwrap_or_else(|_| json!({}));
                    messages.push(CanonicalMessage {
                        role: "assistant".to_string(),
                        content: vec![CanonicalContentBlock::ToolUse { id, name, input }],
                    });
                }
                Some("function_call_output") => {
                    let id = clamp_tool_call_id(
                        item.get("call_id")
                            .and_then(Value::as_str)
                            .unwrap_or("tc_0"),
                    );
                    let content = item
                        .get("output")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    messages.push(CanonicalMessage {
                        role: "user".to_string(),
                        content: vec![CanonicalContentBlock::ToolResult {
                            tool_use_id: id,
                            content,
                            is_error: false,
                        }],
                    });
                }
                _ => {
                    let role = item.get("role").and_then(Value::as_str).unwrap_or("user");
                    let mut blocks = Vec::new();
                    if let Some(s) = item.get("content").and_then(Value::as_str) {
                        blocks.push(CanonicalContentBlock::Text {
                            text: s.to_string(),
                        });
                    } else if let Some(parts) = item.get("content").and_then(Value::as_array) {
                        for p in parts {
                            if let Some(t) = p.get("text").and_then(Value::as_str) {
                                blocks.push(CanonicalContentBlock::Text {
                                    text: t.to_string(),
                                });
                            }
                        }
                    }
                    if !blocks.is_empty() {
                        messages.push(CanonicalMessage {
                            role: role.to_string(),
                            content: blocks,
                        });
                    }
                }
            }
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
                        .get("parameters")
                        .cloned()
                        .unwrap_or_else(|| json!({"type": "object", "properties": {}})),
                });
            }
        }
    }

    let thinking = body
        .get("reasoning")
        .and_then(|r| r.get("effort"))
        .and_then(Value::as_str)
        .map(|e| ThinkingConfig {
            budget_tokens: None,
            effort: Some(e.to_string()),
        });

    Ok(CanonicalRequest {
        model,
        system,
        messages,
        tools,
        tool_choice: body.get("tool_choice").cloned(),
        max_tokens: body.get("max_output_tokens").and_then(Value::as_u64),
        temperature: body.get("temperature").and_then(Value::as_f64),
        stream: body.get("stream").and_then(Value::as_bool).unwrap_or(false),
        thinking,
    })
}

pub fn encode_request(req: &CanonicalRequest) -> Value {
    let mut input_items = Vec::new();
    for msg in &req.messages {
        for b in &msg.content {
            match b {
                CanonicalContentBlock::Text { text } => {
                    let kind = if msg.role == "assistant" {
                        "output_text"
                    } else {
                        "input_text"
                    };
                    input_items.push(json!({
                        "type": "message",
                        "role": msg.role,
                        "content": [{ "type": kind, "text": text }]
                    }));
                }
                CanonicalContentBlock::ImageBase64 { media_type, data } => {
                    input_items.push(json!({
                        "type": "message",
                        "role": msg.role,
                        "content": [{
                            "type": "input_image",
                            "image_url": format!("data:{media_type};base64,{data}")
                        }]
                    }));
                }
                CanonicalContentBlock::ToolUse { id, name, input } => {
                    input_items.push(json!({
                        "type": "function_call",
                        "call_id": clamp_tool_call_id(id),
                        "name": name,
                        "arguments": serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string()),
                    }));
                }
                CanonicalContentBlock::ToolResult {
                    tool_use_id,
                    content,
                    ..
                } => {
                    input_items.push(json!({
                        "type": "function_call_output",
                        "call_id": clamp_tool_call_id(tool_use_id),
                        "output": content,
                    }));
                }
            }
        }
    }

    let mut out = json!({
        "model": req.model,
        "input": input_items,
        "stream": req.stream,
    });
    if !req.system.is_empty() {
        out["instructions"] = json!(req.system.join("\n\n"));
    }
    if let Some(mt) = req.max_tokens {
        out["max_output_tokens"] = json!(mt);
    }
    if !req.tools.is_empty() {
        out["tools"] = Value::Array(
            req.tools
                .iter()
                .map(|t| {
                    json!({
                        "type": "function",
                        "name": t.name,
                        "description": t.description.as_deref().unwrap_or(""),
                        "parameters": t.input_schema,
                    })
                })
                .collect(),
        );
    }
    if let Some(ref tc) = req.tool_choice {
        out["tool_choice"] = tc.clone();
    }
    if let Some(ref th) = req.thinking {
        out["reasoning"] = json!({ "effort": th.to_effort() });
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
        "response.output_text.delta" => {
            if let Some(d) = v.get("delta").and_then(Value::as_str) {
                out.push(CanonicalStreamEvent::TextDelta(d.to_string()));
            }
        }
        "response.reasoning_summary_text.delta" | "response.reasoning.delta" => {
            if let Some(d) = v.get("delta").and_then(Value::as_str) {
                out.push(CanonicalStreamEvent::ReasoningDelta(d.to_string()));
            }
        }
        "response.output_item.added" => {
            if let Some(item) = v.get("item")
                && item.get("type").and_then(Value::as_str) == Some("function_call")
            {
                let index = v.get("output_index").and_then(Value::as_u64).unwrap_or(0) as usize;
                let id = clamp_tool_call_id(
                    item.get("call_id")
                        .or_else(|| item.get("id"))
                        .and_then(Value::as_str)
                        .unwrap_or("tc_0"),
                );
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                out.push(CanonicalStreamEvent::ToolCallStart { index, id, name });
            }
        }
        "response.function_call_arguments.delta" => {
            let index = v.get("output_index").and_then(Value::as_u64).unwrap_or(0) as usize;
            if let Some(d) = v.get("delta").and_then(Value::as_str) {
                out.push(CanonicalStreamEvent::ToolCallArgsDelta {
                    index,
                    delta: d.to_string(),
                });
            }
        }
        "response.completed" => {
            if let Some(u) = v.get("response").and_then(|r| r.get("usage"))
                && let (Some(i), Some(o)) = (
                    u.get("input_tokens").and_then(Value::as_u64),
                    u.get("output_tokens").and_then(Value::as_u64),
                )
            {
                out.push(CanonicalStreamEvent::Usage {
                    input_tokens: i,
                    output_tokens: o,
                });
            }
            out.push(CanonicalStreamEvent::Finish {
                reason: "stop".to_string(),
            });
        }
        _ => {}
    }
    out
}

pub fn encode_sse_event(ev: &CanonicalStreamEvent, model: &str) -> Vec<String> {
    match ev {
        CanonicalStreamEvent::TextDelta(t) => vec![format!(
            "event: response.output_text.delta\ndata: {}\n\n",
            json!({ "type": "response.output_text.delta", "delta": t })
        )],
        CanonicalStreamEvent::ReasoningDelta(r) => vec![format!(
            "event: response.reasoning_summary_text.delta\ndata: {}\n\n",
            json!({ "type": "response.reasoning_summary_text.delta", "delta": r })
        )],
        CanonicalStreamEvent::ToolCallStart { index, id, name } => vec![format!(
            "event: response.output_item.added\ndata: {}\n\n",
            json!({
                "type": "response.output_item.added",
                "output_index": index,
                "item": { "type": "function_call", "call_id": clamp_tool_call_id(id), "name": name, "arguments": "" }
            })
        )],
        CanonicalStreamEvent::ToolCallArgsDelta { index, delta } => vec![format!(
            "event: response.function_call_arguments.delta\ndata: {}\n\n",
            json!({ "type": "response.function_call_arguments.delta", "output_index": index, "delta": delta })
        )],
        CanonicalStreamEvent::ToolCallEnd { .. } => Vec::new(),
        CanonicalStreamEvent::Usage {
            input_tokens,
            output_tokens,
        } => vec![format!(
            "event: response.completed\ndata: {}\n\n",
            json!({
                "type": "response.completed",
                "response": {
                    "model": model,
                    "status": "completed",
                    "usage": { "input_tokens": input_tokens, "output_tokens": output_tokens }
                }
            })
        )],
        CanonicalStreamEvent::Finish { .. } => vec![format!(
            "event: response.done\ndata: {}\n\n",
            json!({ "type": "response.done", "status": "completed" })
        )],
        CanonicalStreamEvent::Error { message } => vec![format!(
            "event: error\ndata: {}\n\n",
            json!({ "type": "error", "error": { "message": message } })
        )],
    }
}
