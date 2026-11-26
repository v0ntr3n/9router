use ninerouter_rs::translator;
use ninerouter_rs::translator::ir::{
    CanonicalStreamEvent, ThinkingConfig, WireFormat, clamp_tool_call_id,
};
use serde_json::json;

#[test]
fn deterministic_tool_call_id_clamping_and_thinking_thresholds() {
    let long_id = "call_".to_string() + &"x".repeat(80);
    let c1 = clamp_tool_call_id(&long_id);
    let c2 = clamp_tool_call_id(&long_id);
    assert_eq!(c1, c2);
    assert!(c1.len() <= 64);
    assert!(c1.starts_with("tc_"));

    assert_eq!(
        ThinkingConfig {
            budget_tokens: Some(4096),
            effort: None
        }
        .to_effort(),
        "low"
    );
    assert_eq!(
        ThinkingConfig {
            budget_tokens: Some(10000),
            effort: None
        }
        .to_effort(),
        "medium"
    );
    assert_eq!(
        ThinkingConfig {
            budget_tokens: Some(24000),
            effort: None
        }
        .to_effort(),
        "high"
    );
}

#[test]
fn cross_format_request_and_sse_roundtrip() {
    let anthropic_req = json!({
        "model": "claude-sonnet-4-5",
        "max_tokens": 2048,
        "system": "Be concise",
        "thinking": { "type": "enabled", "budget_tokens": 8192 },
        "stream": true,
        "messages": [
            {
                "role": "user",
                "content": [
                    { "type": "text", "text": "Inspect this image" },
                    { "type": "image", "source": { "type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo=" } }
                ]
            }
        ],
        "tools": [
            { "name": "lookup", "description": "Look up item", "input_schema": { "type": "object", "properties": {} } }
        ]
    });

    let ir = translator::decode_request(WireFormat::AnthropicMessages, &anthropic_req).unwrap();
    assert_eq!(ir.system, vec!["Be concise"]);
    assert_eq!(ir.thinking.as_ref().unwrap().to_effort(), "medium");

    let openai_chat = translator::encode_request(WireFormat::OpenAiChat, &ir);
    assert_eq!(openai_chat["reasoning_effort"], "medium");
    assert_eq!(openai_chat["tools"][0]["function"]["name"], "lookup");

    let openai_resp = translator::encode_request(WireFormat::OpenAiResponses, &ir);
    assert_eq!(openai_resp["reasoning"]["effort"], "medium");
    assert_eq!(openai_resp["instructions"], "Be concise");

    // SSE chunk cross-format translation: OpenAI Chat -> Anthropic Messages
    let chunk = r#"{"choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":null}]}"#;
    let events = translator::decode_sse_chunk(WireFormat::OpenAiChat, None, chunk);
    assert_eq!(
        events,
        vec![CanonicalStreamEvent::TextDelta("hello".to_string())]
    );
    let encoded = translator::encode_sse_event(
        WireFormat::AnthropicMessages,
        &events[0],
        "claude-sonnet-4-5",
    );
    assert!(encoded[0].contains("text_delta"));
    assert!(encoded[0].contains("hello"));
}
