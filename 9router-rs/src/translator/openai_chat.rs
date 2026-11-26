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
    let mut messages = Vec::new();

    if let Some(arr) = body.get("messages").and_then(Value::as_array) {
        for m in arr {
            let role = m.get("role").and_then(Value::as_str).unwrap_or("user");
            if matches!(role, "system" | "developer") {
                if let Some(s) = m.get("content").and_then(Value::as_str) {
                    system.push(s.to_string());
                }
                continue;
            }
            if role == "tool" {
                let id = clamp_tool_call_id(
                    m.get("tool_call_id")
                        .and_then(Value::as_str)
                        .unwrap_or("tc_0"),
                );
                let content = m
                    .get("content")
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
                continue;
            }

            let mut blocks = Vec::new();
            if let Some(s) = m.get("content").and_then(Value::as_str) {
                if !s.is_empty() {
                    blocks.push(CanonicalContentBlock::Text {
                        text: s.to_string(),
                    });
                }
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
                        Some("image_url") => {
                            if let Some(url) = p
                                .get("image_url")
                                .and_then(|u| u.get("url"))
                                .and_then(Value::as_str)
                                && let Some((meta, data)) = url.split_once(";base64,")
                            {
                                let media_type =
                                    meta.strip_prefix("data:").unwrap_or("image/png").to_string();
                                blocks.push(CanonicalContentBlock::ImageBase64 {
                                    media_type,
                                    data: data.to_string(),
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }

            if let Some(tcs) = m.get("tool_calls").and_then(Value::as_array) {
                for tc in tcs {
                    let id =
                        clamp_tool_call_id(tc.get("id").and_then(Value::as_str).unwrap_or("tc_0"));
                    let name = tc
                        .get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let args_str = tc
                        .get("function")
                        .and_then(|f| f.get("arguments"))
                        .and_then(Value::as_str)
                        .unwrap_or("{}");
                    let input: Value = serde_json::from_str(args_str).unwrap_or_else(|_| json!({}));
                    blocks.push(CanonicalContentBlock::ToolUse { id, name, input });
                }
            }

            messages.push(CanonicalMessage {
                role: role.to_string(),
                content: blocks,
            });
        }
    }

    let mut tools = Vec::new();
    if let Some(arr) = body.get("tools").and_then(Value::as_array) {
        for t in arr {
            let f = t.get("function").unwrap_or(t);
            if let Some(name) = f.get("name").and_then(Value::as_str) {
                tools.push(CanonicalTool {
                    name: name.to_string(),
                    description: f
                        .get("description")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    input_schema: f
                        .get("parameters")
                        .cloned()
                        .unwrap_or_else(|| json!({"type": "object", "properties": {}})),
                });
            }
        }
    }

    let thinking = body
        .get("reasoning_effort")
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
        max_tokens: body
            .get("max_completion_tokens")
            .or_else(|| body.get("max_tokens"))
            .and_then(Value::as_u64),
        temperature: body.get("temperature").and_then(Value::as_f64),
        stream: body.get("stream").and_then(Value::as_bool).unwrap_or(false),
        thinking,
    })
}

pub fn encode_request(req: &CanonicalRequest) -> Value {
    let mut messages = Vec::new();
    if !req.system.is_empty() {
        messages.push(json!({
            "role": "system",
            "content": req.system.join("\n\n"),
        }));
    }

    for msg in &req.messages {
        let mut text_parts = Vec::new();
        let mut tool_calls = Vec::new();
        let mut tool_results = Vec::new();

        for b in &msg.content {
            match b {
                CanonicalContentBlock::Text { text } => {
                    text_parts.push(json!({ "type": "text", "text": text }));
                }
                CanonicalContentBlock::ImageBase64 { media_type, data } => {
                    text_parts.push(json!({
                        "type": "image_url",
                        "image_url": { "url": format!("data:{media_type};base64,{data}") }
                    }));
                }
                CanonicalContentBlock::ToolUse { id, name, input } => {
                    tool_calls.push(json!({
                        "id": clamp_tool_call_id(id),
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string()),
                        }
                    }));
                }
                CanonicalContentBlock::ToolResult {
                    tool_use_id,
                    content,
                    ..
                } => {
                    tool_results.push(json!({
                        "role": "tool",
                        "tool_call_id": clamp_tool_call_id(tool_use_id),
                        "content": content,
                    }));
                }
            }
        }

        if !text_parts.is_empty() || !tool_calls.is_empty() {
            let content_val = if text_parts.len() == 1
                && text_parts[0].get("type").and_then(Value::as_str) == Some("text")
            {
                text_parts[0]["text"].clone()
            } else if text_parts.is_empty() {
                Value::Null
            } else {
                Value::Array(text_parts)
            };
            let mut m = json!({ "role": msg.role, "content": content_val });
            if !tool_calls.is_empty() {
                m["tool_calls"] = Value::Array(tool_calls);
            }
            messages.push(m);
        }
        messages.extend(tool_results);
    }

    let mut out = json!({
        "model": req.model,
        "messages": messages,
        "stream": req.stream,
    });
    if let Some(mt) = req.max_tokens {
        out["max_tokens"] = json!(mt);
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
                        "type": "function",
                        "function": {
                            "name": t.name,
                            "description": t.description.as_deref().unwrap_or(""),
                            "parameters": t.input_schema,
                        }
                    })
                })
                .collect(),
        );
    }
    if let Some(ref tc) = req.tool_choice {
        out["tool_choice"] = tc.clone();
    }
    if let Some(ref th) = req.thinking {
        out["reasoning_effort"] = json!(th.to_effort());
    }
    out
}

pub fn decode_sse_chunk(data: &str) -> Vec<CanonicalStreamEvent> {
    let trimmed = data.trim();
    if trimmed == "[DONE]" || trimmed.is_empty() {
        return Vec::new();
    }
    let Ok(v) = serde_json::from_str::<Value>(trimmed) else {
        return Vec::new();
    };
    let mut events = Vec::new();

    if let Some(usage) = v.get("usage")
        && let (Some(i), Some(o)) = (
            usage.get("prompt_tokens").and_then(Value::as_u64),
            usage.get("completion_tokens").and_then(Value::as_u64),
        )
    {
        events.push(CanonicalStreamEvent::Usage {
            input_tokens: i,
            output_tokens: o,
        });
    }

    if let Some(choice) = v
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
    {
        if let Some(delta) = choice.get("delta") {
            if let Some(r) = delta.get("reasoning_content").and_then(Value::as_str)
                && !r.is_empty()
            {
                events.push(CanonicalStreamEvent::ReasoningDelta(r.to_string()));
            }
            if let Some(c) = delta.get("content").and_then(Value::as_str)
                && !c.is_empty()
            {
                events.push(CanonicalStreamEvent::TextDelta(c.to_string()));
            }
            if let Some(tcs) = delta.get("tool_calls").and_then(Value::as_array) {
                for tc in tcs {
                    let index = tc.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                    if let Some(name) = tc
                        .get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(Value::as_str)
                        && !name.is_empty()
                    {
                        let id = clamp_tool_call_id(
                            tc.get("id").and_then(Value::as_str).unwrap_or("tc_0"),
                        );
                        events.push(CanonicalStreamEvent::ToolCallStart {
                            index,
                            id,
                            name: name.to_string(),
                        });
                    }
                    if let Some(args) = tc
                        .get("function")
                        .and_then(|f| f.get("arguments"))
                        .and_then(Value::as_str)
                        && !args.is_empty()
                    {
                        events.push(CanonicalStreamEvent::ToolCallArgsDelta {
                            index,
                            delta: args.to_string(),
                        });
                    }
                }
            }
        }
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            events.push(CanonicalStreamEvent::Finish {
                reason: reason.to_string(),
            });
        }
    }
    events
}

pub fn encode_sse_event(ev: &CanonicalStreamEvent, model: &str) -> Vec<String> {
    let payload = match ev {
        CanonicalStreamEvent::TextDelta(t) => json!({
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [{ "index": 0, "delta": { "content": t }, "finish_reason": null }]
        }),
        CanonicalStreamEvent::ReasoningDelta(r) => json!({
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [{ "index": 0, "delta": { "reasoning_content": r }, "finish_reason": null }]
        }),
        CanonicalStreamEvent::ToolCallStart { index, id, name } => json!({
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [{
                "index": 0,
                "delta": { "tool_calls": [{ "index": index, "id": clamp_tool_call_id(id), "type": "function", "function": { "name": name, "arguments": "" } }] },
                "finish_reason": null
            }]
        }),
        CanonicalStreamEvent::ToolCallArgsDelta { index, delta } => json!({
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [{
                "index": 0,
                "delta": { "tool_calls": [{ "index": index, "function": { "arguments": delta } }] },
                "finish_reason": null
            }]
        }),
        CanonicalStreamEvent::ToolCallEnd { .. } => return Vec::new(),
        CanonicalStreamEvent::Usage {
            input_tokens,
            output_tokens,
        } => json!({
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [],
            "usage": {
                "prompt_tokens": input_tokens,
                "completion_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens
            }
        }),
        CanonicalStreamEvent::Finish { reason } => {
            let chunk = json!({
                "object": "chat.completion.chunk",
                "model": model,
                "choices": [{ "index": 0, "delta": {}, "finish_reason": reason }]
            });
            return vec![format!("data: {chunk}\n\n"), "data: [DONE]\n\n".to_string()];
        }
        CanonicalStreamEvent::Error { message } => json!({
            "error": { "type": "stream_error", "message": message }
        }),
    };
    vec![format!("data: {payload}\n\n")]
}
