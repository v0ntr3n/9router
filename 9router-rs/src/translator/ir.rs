use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WireFormat {
    OpenAiChat,
    OpenAiResponses,
    AnthropicMessages,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalRequest {
    pub model: String,
    pub system: Vec<String>,
    pub messages: Vec<CanonicalMessage>,
    pub tools: Vec<CanonicalTool>,
    pub tool_choice: Option<Value>,
    pub max_tokens: Option<u64>,
    pub temperature: Option<f64>,
    pub stream: bool,
    pub thinking: Option<ThinkingConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalMessage {
    pub role: String,
    pub content: Vec<CanonicalContentBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CanonicalContentBlock {
    Text {
        text: String,
    },
    ImageBase64 {
        media_type: String,
        data: String,
    },
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalTool {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThinkingConfig {
    pub budget_tokens: Option<u64>,
    pub effort: Option<String>,
}

impl ThinkingConfig {
    pub fn to_effort(&self) -> &'static str {
        if let Some(ref e) = self.effort {
            return match e.as_str() {
                "low" => "low",
                "high" => "high",
                _ => "medium",
            };
        }
        match self.budget_tokens.unwrap_or(10240) {
            0..=4096 => "low",
            4097..=16384 => "medium",
            _ => "high",
        }
    }

    pub fn to_budget_tokens(&self) -> u64 {
        if let Some(b) = self.budget_tokens {
            return b;
        }
        match self.effort.as_deref() {
            Some("low") => 4096,
            Some("high") => 24576,
            _ => 10240,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CanonicalStreamEvent {
    TextDelta(String),
    ReasoningDelta(String),
    ToolCallStart {
        index: usize,
        id: String,
        name: String,
    },
    ToolCallArgsDelta {
        index: usize,
        delta: String,
    },
    ToolCallEnd {
        index: usize,
    },
    Usage {
        input_tokens: u64,
        output_tokens: u64,
    },
    Finish {
        reason: String,
    },
    Error {
        message: String,
    },
}

/// Deterministic <= 64-char tool-call ID clamping applied symmetrically to tool_use.id and tool_result.tool_use_id.
pub fn clamp_tool_call_id(id: &str) -> String {
    if id.len() <= 64 {
        return id.to_string();
    }
    let digest = Sha256::digest(id.as_bytes());
    let hex_str = hex::encode(digest);
    format!("tc_{}", &hex_str[..32])
}
