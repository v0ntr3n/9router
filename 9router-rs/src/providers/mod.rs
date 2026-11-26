pub mod anthropic;
pub mod openai;
pub mod opencode;
pub mod opencode_fingerprint;

use crate::translator::ir::WireFormat;
use bytes::Bytes;
use futures_util::Stream;
use std::pin::Pin;

pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, String>> + Send>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderId {
    OpenCode,
    OpenAi,
    Anthropic,
}

impl ProviderId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OpenCode => "opencode",
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "opencode" | "oc" => Some(Self::OpenCode),
            "openai" => Some(Self::OpenAi),
            "anthropic" | "claude" => Some(Self::Anthropic),
            _ => None,
        }
    }

    pub fn is_paid(&self) -> bool {
        matches!(self, Self::OpenAi | Self::Anthropic)
    }

    pub fn native_format(&self, model: &str) -> WireFormat {
        match self {
            Self::Anthropic => WireFormat::AnthropicMessages,
            Self::OpenAi => {
                if model.starts_with("gpt-5") || model.starts_with("o3") {
                    WireFormat::OpenAiResponses
                } else {
                    WireFormat::OpenAiChat
                }
            }
            Self::OpenCode => {
                if model.contains("gpt-5") {
                    WireFormat::OpenAiResponses
                } else if model.contains("minimax") {
                    WireFormat::AnthropicMessages
                } else {
                    WireFormat::OpenAiChat
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderErrorKind {
    Overloaded,
    FreeUsageLimit,
    AuthFailed,
    FingerprintRejected,
    TunnelError,
    Upstream5xx,
    ClientError(u16),
}

#[derive(Debug, Clone)]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
    pub status: u16,
    pub message: String,
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} (HTTP {}): {}",
            self.kind, self.status, self.message
        )
    }
}

impl std::error::Error for ProviderError {}

pub struct UpstreamResponse {
    pub status: u16,
    pub content_type: String,
    pub is_sse: bool,
    pub stream: ByteStream,
}
