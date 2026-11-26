use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use super::atomic_write;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SecretsBundle {
    pub openai_api_key: Option<String>,
    pub anthropic_api_key: Option<String>,
    pub hma_wallet_key: Option<String>,
    pub hma_container_id: Option<String>,
    pub hma_device_fingerprint: Option<String>,
    pub hma_device_udid: Option<String>,
    pub hma_access_token: Option<String>,
    pub hma_refresh_token: Option<String>,
    pub local_api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretMask {
    pub configured: bool,
    pub last4: Option<String>,
}

impl SecretMask {
    pub fn from_opt(val: &Option<String>) -> Self {
        match val.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(s) => {
                let last4 = if s.len() >= 4 {
                    Some(s[s.len() - 4..].to_string())
                } else {
                    Some("****".to_string())
                };
                Self {
                    configured: true,
                    last4,
                }
            }
            None => Self {
                configured: false,
                last4: None,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsStatus {
    pub openai: SecretMask,
    pub anthropic: SecretMask,
    pub local_api_key: SecretMask,
    pub hma: SecretMask,
}

impl SecretsBundle {
    pub fn status(&self) -> SecretsStatus {
        SecretsStatus {
            openai: SecretMask::from_opt(&self.openai_api_key),
            anthropic: SecretMask::from_opt(&self.anthropic_api_key),
            local_api_key: SecretMask::from_opt(&self.local_api_key),
            hma: SecretMask::from_opt(&self.hma_access_token),
        }
    }

    pub fn hma_activated(&self) -> bool {
        self.hma_access_token
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
    }
}

pub fn load_secrets(data_dir: &Path) -> Result<SecretsBundle> {
    let path = data_dir.join("secrets.bin");
    if !path.exists() {
        return Ok(SecretsBundle::default());
    }
    let raw = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let plain = unprotect_bytes(&raw)?;
    serde_json::from_slice(&plain).context("failed to deserialize secrets bundle")
}

pub fn save_secrets(data_dir: &Path, bundle: &SecretsBundle) -> Result<()> {
    let plain = serde_json::to_vec(bundle).context("failed to serialize secrets bundle")?;
    let protected = protect_bytes(&plain)?;
    atomic_write(&data_dir.join("secrets.bin"), &protected)
}

#[cfg(windows)]
fn protect_bytes(plain: &[u8]) -> Result<Vec<u8>> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptProtectData};

    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(plain.len()).context("secrets payload too large")?,
        pbData: plain.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    // SAFETY: input points to valid slice memory for the duration of the call; output is freed via LocalFree.
    let ok = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        anyhow::bail!("Windows DPAPI CryptProtectData failed");
    }
    let result = unsafe {
        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let vec = slice.to_vec();
        LocalFree(output.pbData as _);
        vec
    };
    Ok(result)
}

#[cfg(windows)]
fn unprotect_bytes(protected: &[u8]) -> Result<Vec<u8>> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptUnprotectData};

    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(protected.len()).context("secrets payload too large")?,
        pbData: protected.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };

    // SAFETY: input points to valid slice memory; output is freed via LocalFree.
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            0,
            &mut output,
        )
    };
    if ok == 0 {
        anyhow::bail!("Windows DPAPI CryptUnprotectData failed");
    }
    let result = unsafe {
        let slice = std::slice::from_raw_parts(output.pbData, output.cbData as usize);
        let vec = slice.to_vec();
        LocalFree(output.pbData as _);
        vec
    };
    Ok(result)
}

#[cfg(not(windows))]
fn protect_bytes(plain: &[u8]) -> Result<Vec<u8>> {
    // Non-Windows test/dev fallback (Windows x64 builds use CryptProtectData above).
    Ok(plain.to_vec())
}

#[cfg(not(windows))]
fn unprotect_bytes(protected: &[u8]) -> Result<Vec<u8>> {
    Ok(protected.to_vec())
}
