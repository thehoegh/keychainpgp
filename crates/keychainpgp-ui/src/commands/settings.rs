//! Tauri commands for application settings.

use std::sync::atomic::Ordering;

use keychainpgp_core::Error as CoreError;
use keychainpgp_core::types::{ArmorHeaders, DEFAULT_ARMOR_COMMENT};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use tauri_plugin_store::StoreExt;

use crate::state::AppState;

/// Settings file name used in portable mode.
const PORTABLE_SETTINGS_FILE: &str = "settings.json";

/// Application settings exposed to the frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Auto-clear clipboard after decryption.
    pub auto_clear_enabled: bool,
    /// Auto-clear delay in seconds.
    pub auto_clear_delay_secs: u64,
    /// Also auto-clear after encryption.
    pub auto_clear_after_encrypt: bool,
    /// Monitor clipboard for PGP content.
    pub clipboard_monitoring: bool,
    /// Always encrypt to self.
    pub encrypt_to_self: bool,
    /// Which own keys to encrypt to (fingerprints). Empty = all own keys.
    #[serde(default)]
    pub encrypt_to_self_keys: Vec<String>,
    /// UI theme: "light", "dark", or "system".
    pub theme: String,
    /// Passphrase cache duration in seconds (0 = disabled).
    pub passphrase_cache_secs: u64,
    #[serde(default = "default_keyserver_url")]
    pub keyserver_url: String,
    /// Unverified keyservers for search and upload (comma-separated).
    #[serde(default = "default_unverified_keyserver_url")]
    pub unverified_keyserver_url: String,
    /// Include armor headers (Version, Comment, key info) in PGP output.
    #[serde(default)]
    pub include_armor_headers: bool,
    /// Emit the `Version` armor header when armor headers are enabled.
    #[serde(default = "default_true")]
    pub include_version_header: bool,
    /// `Comment` armor header value. Empty omits the header.
    #[serde(default = "default_armor_comment")]
    pub armor_comment: String,
    /// User's preferred display language. "auto" = detect from OS.
    #[serde(default = "default_locale")]
    pub locale: String,
    /// SOCKS5 proxy URL for anonymous keyserver access (e.g., "socks5h://127.0.0.1:9050").
    #[serde(default = "default_proxy_url")]
    pub proxy_url: String,
    /// Whether the proxy is active for keyserver requests.
    #[serde(default)]
    pub proxy_enabled: bool,
    /// Proxy preset: "tor", "lokinet", or "custom".
    #[serde(default = "default_proxy_preset")]
    pub proxy_preset: String,
    /// Close to system tray instead of quitting when the window is closed.
    #[serde(default)]
    pub close_to_tray: bool,
    /// OPSEC mode: hardened operation for high-risk users.
    #[serde(default)]
    pub opsec_mode: bool,
    /// OPSEC: custom window title (empty = "Notes").
    #[serde(default = "default_opsec_title")]
    pub opsec_window_title: String,
    /// OPSEC: view timeout in seconds for decrypted text (0 = no timeout).
    #[serde(default = "default_opsec_view_timeout")]
    pub opsec_view_timeout_secs: u64,
}

fn default_true() -> bool {
    true
}
fn default_armor_comment() -> String {
    DEFAULT_ARMOR_COMMENT.into()
}
fn default_locale() -> String {
    "auto".into()
}
fn default_proxy_url() -> String {
    "socks5h://127.0.0.1:9050".into()
}
fn default_proxy_preset() -> String {
    "tor".into()
}
fn default_keyserver_url() -> String {
    "https://keys.openpgp.org".into()
}
fn default_unverified_keyserver_url() -> String {
    "https://keyserver.ubuntu.com".into()
}
fn default_opsec_title() -> String {
    "Notes".into()
}
fn default_opsec_view_timeout() -> u64 {
    30
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_clear_enabled: true,
            auto_clear_delay_secs: 30,
            auto_clear_after_encrypt: false,
            clipboard_monitoring: true,
            encrypt_to_self: true,
            encrypt_to_self_keys: Vec::new(),
            theme: "system".into(),
            passphrase_cache_secs: 600,
            keyserver_url: "https://keys.openpgp.org".into(),
            unverified_keyserver_url: "https://keyserver.ubuntu.com".into(),
            include_armor_headers: false,
            include_version_header: true,
            armor_comment: default_armor_comment(),
            locale: "auto".into(),
            proxy_url: "socks5h://127.0.0.1:9050".into(),
            proxy_enabled: false,
            proxy_preset: "tor".into(),
            close_to_tray: false,
            opsec_mode: false,
            opsec_window_title: "Notes".into(),
            opsec_view_timeout_secs: 30,
        }
    }
}

impl Settings {
    /// Armor headers to emit. OPSEC mode suppresses all of them.
    ///
    /// A comment the engine would reject is omitted so the version and key
    /// info headers can still be applied.
    pub fn armor_headers(&self) -> ArmorHeaders {
        if self.opsec_mode || !self.include_armor_headers {
            return ArmorHeaders::default();
        }
        ArmorHeaders {
            version: self.include_version_header,
            comment: sanitize_armor_comment(&self.armor_comment)
                .ok()
                .filter(|comment| !comment.is_empty()),
            key_info: true,
        }
    }
}

/// Trim `raw` into a comment [`ArmorHeaders::validate`] accepts.
///
/// An empty string omits the header. Control characters and over-long values
/// are rejected with the validator's reason.
fn sanitize_armor_comment(raw: &str) -> Result<String, String> {
    let comment = raw.trim();
    if comment.is_empty() {
        return Ok(String::new());
    }
    let headers = ArmorHeaders {
        comment: Some(comment.to_string()),
        ..ArmorHeaders::default()
    };
    match headers.validate() {
        Ok(()) => Ok(comment.to_string()),
        Err(CoreError::InvalidArmorHeader { reason }) => Err(reason),
        Err(other) => Err(other.to_string()),
    }
}

/// Settings to persist, and an error when the incoming comment cannot be stored.
///
/// A rejected comment is replaced with the previous safe value, or cleared when
/// that value is also unsafe. The other fields are kept so the rest of the
/// update can still be saved.
fn prepare_settings_update(
    mut incoming: Settings,
    previous: &Settings,
) -> (Settings, Result<(), String>) {
    match sanitize_armor_comment(&incoming.armor_comment) {
        Ok(comment) => {
            incoming.armor_comment = comment;
            (incoming, Ok(()))
        }
        Err(reason) => {
            tracing::warn!("rejecting armor comment: {reason}");
            incoming.armor_comment =
                sanitize_armor_comment(&previous.armor_comment).unwrap_or_default();
            // The settings store matches this prefix before reloading the snapshot.
            (
                incoming,
                Err(format!("Couldn't save the armor comment: {reason}")),
            )
        }
    }
}

const SETTINGS_KEY: &str = "settings";

/// Check if the app is running in portable mode.
#[tauri::command]
pub fn is_portable(state: State<'_, AppState>) -> bool {
    state.portable
}

/// Get the current application settings.
#[tauri::command]
pub fn get_settings(app: AppHandle, state: State<'_, AppState>) -> Settings {
    get_settings_internal(&app, &state)
}

/// Internal helper to get settings from portable dir or Tauri store.
pub fn get_settings_internal(app: &AppHandle, state: &AppState) -> Settings {
    // In portable mode, read directly from the portable data dir
    if let Some(ref portable_dir) = state.portable_dir {
        let path = portable_dir.join(PORTABLE_SETTINGS_FILE);
        if let Ok(data) = std::fs::read_to_string(&path) {
            if let Ok(s) = serde_json::from_str::<Settings>(&data) {
                return s;
            }
        }
        return Settings::default();
    }

    // Normal mode: use Tauri plugin store
    let store = match app.store("settings.json") {
        Ok(s) => s,
        Err(_) => return Settings::default(),
    };

    match store.get(SETTINGS_KEY) {
        Some(val) => serde_json::from_value(val).unwrap_or_default(),
        None => Settings::default(),
    }
}

/// Update application settings.
#[tauri::command]
pub fn update_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: Settings,
) -> Result<(), String> {
    let previous = get_settings_internal(&app, &state);
    let (settings, comment_result) = prepare_settings_update(settings, &previous);

    // Applying headers must not abort the save. Prepared comments pass
    // validation; if this still fails, the engine keeps its previous headers.
    if let Err(e) = state.engine.set_armor_headers(settings.armor_headers()) {
        tracing::warn!("armor headers were not applied: {e}");
    }
    state
        .close_to_tray
        .store(settings.close_to_tray, Ordering::Relaxed);

    // Sync passphrase cache TTL
    if let Ok(mut cache) = state.passphrase_cache.lock() {
        cache.set_ttl(settings.passphrase_cache_secs);
    }

    // In portable mode, write directly to the portable data dir
    if let Some(ref portable_dir) = state.portable_dir {
        let path = portable_dir.join(PORTABLE_SETTINGS_FILE);
        let json =
            serde_json::to_string_pretty(&settings).map_err(|e| format!("Serialize error: {e}"))?;
        std::fs::write(&path, json)
            .map_err(|e| format!("Failed to write portable settings: {e}"))?;
        tracing::info!("settings updated (portable)");
        return comment_result;
    }

    // Normal mode: use Tauri plugin store
    let store = app
        .store("settings.json")
        .map_err(|e| format!("Failed to open settings store: {e}"))?;

    let val = serde_json::to_value(&settings).map_err(|e| format!("Serialize error: {e}"))?;
    store.set(SETTINGS_KEY, val);

    tracing::info!("settings updated");
    comment_result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_comment(comment: &str) -> Settings {
        Settings {
            include_armor_headers: true,
            armor_comment: comment.to_string(),
            ..Settings::default()
        }
    }

    #[test]
    fn armor_headers_skip_comments_the_engine_would_reject() {
        let long = "x".repeat(keychainpgp_core::types::MAX_ARMOR_COMMENT_LEN + 1);
        for comment in [
            "inner\ttab",
            "line\nbreak",
            "carriage\rreturn",
            long.as_str(),
        ] {
            let headers = with_comment(comment).armor_headers();
            assert!(
                headers.validate().is_ok(),
                "{comment:?} produced invalid headers"
            );
            assert!(headers.comment.is_none(), "{comment:?} was emitted");
            assert!(headers.version, "version header should still be emitted");
            assert!(headers.key_info);
        }
    }

    #[test]
    fn armor_headers_trim_a_normal_comment() {
        let headers = with_comment("  from my laptop  ").armor_headers();
        assert_eq!(headers.comment.as_deref(), Some("from my laptop"));
        assert!(headers.validate().is_ok());
    }

    #[test]
    fn rejected_comment_keeps_the_previous_value_and_other_fields() {
        let mut incoming = with_comment("hello\tworld");
        incoming.theme = "dark".into();
        incoming.close_to_tray = true;

        let previous = with_comment("kept");
        let (prepared, result) = prepare_settings_update(incoming, &previous);
        let err = result.expect_err("unsafe comment should be rejected");

        assert!(err.contains("Couldn't save the armor comment"), "{err}");
        assert!(err.contains("control characters"), "{err}");
        assert_eq!(prepared.armor_comment, "kept");
        assert_eq!(prepared.theme, "dark");
        assert!(prepared.close_to_tray);
        let engine = keychainpgp_core::SequoiaEngine::new();
        engine
            .set_armor_headers(prepared.armor_headers())
            .expect("prepared headers must be safe to apply");
        assert_eq!(prepared.armor_headers().comment.as_deref(), Some("kept"));
    }

    #[test]
    fn rejected_comment_clears_an_unsafe_stored_value() {
        let incoming = with_comment("also\nbad");
        let previous = with_comment("stored\tbad");
        let (prepared, result) = prepare_settings_update(incoming, &previous);

        assert!(result.is_err());
        assert_eq!(prepared.armor_comment, "");
        assert!(prepared.armor_headers().comment.is_none());
        assert!(prepared.armor_headers().validate().is_ok());
    }

    #[test]
    fn accepted_comment_is_trimmed() {
        let incoming = with_comment("  ok  ");
        let previous = Settings::default();
        let (prepared, result) = prepare_settings_update(incoming, &previous);

        assert!(result.is_ok());
        assert_eq!(prepared.armor_comment, "ok");
    }
}
