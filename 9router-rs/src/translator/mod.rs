pub mod anthropic_messages;
pub mod ir;
pub mod openai_chat;
pub mod openai_responses;

use anyhow::Result;
use ir::{CanonicalRequest, CanonicalStreamEvent, WireFormat};
use serde_json::Value;

pub fn decode_request(format: WireFormat, body: &Value) -> Result<CanonicalRequest> {
    match format {
        WireFormat::OpenAiChat => openai_chat::decode_request(body),
        WireFormat::OpenAiResponses => openai_responses::decode_request(body),
        WireFormat::AnthropicMessages => anthropic_messages::decode_request(body),
    }
}

pub fn encode_request(format: WireFormat, req: &CanonicalRequest) -> Value {
    match format {
        WireFormat::OpenAiChat => openai_chat::encode_request(req),
        WireFormat::OpenAiResponses => openai_responses::encode_request(req),
        WireFormat::AnthropicMessages => anthropic_messages::encode_request(req),
    }
}

pub fn decode_sse_chunk(
    format: WireFormat,
    event_type: Option<&str>,
    data: &str,
) -> Vec<CanonicalStreamEvent> {
    match format {
        WireFormat::OpenAiChat => openai_chat::decode_sse_chunk(data),
        WireFormat::OpenAiResponses => openai_responses::decode_sse_chunk(event_type, data),
        WireFormat::AnthropicMessages => anthropic_messages::decode_sse_chunk(event_type, data),
    }
}

pub fn encode_sse_event(format: WireFormat, ev: &CanonicalStreamEvent, model: &str) -> Vec<String> {
    match format {
        WireFormat::OpenAiChat => openai_chat::encode_sse_event(ev, model),
        WireFormat::OpenAiResponses => openai_responses::encode_sse_event(ev, model),
        WireFormat::AnthropicMessages => anthropic_messages::encode_sse_event(ev, model),
    }
}
