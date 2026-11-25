import type { Settings } from "$lib/tauri";
import { getSettings, updateSettings } from "$lib/tauri";
import { appStore } from "$lib/stores/app.svelte";

/** Mirrors `DEFAULT_ARMOR_COMMENT` and `MAX_ARMOR_COMMENT_LEN` in keychainpgp-core. */
export const DEFAULT_ARMOR_COMMENT = "https://github.com/thehoegh/keychainpgp";
export const MAX_ARMOR_COMMENT_LEN = 64;

const defaults: Settings = {
  auto_clear_enabled: true,
  auto_clear_delay_secs: 30,
  auto_clear_after_encrypt: false,
  clipboard_monitoring: true,
  encrypt_to_self: true,
  encrypt_to_self_keys: [],
  theme: "system",
  passphrase_cache_secs: 600,
  keyserver_url: "https://keys.openpgp.org",
  unverified_keyserver_url: "https://keyserver.ubuntu.com",
  include_armor_headers: false,
  include_version_header: true,
  armor_comment: DEFAULT_ARMOR_COMMENT,
  locale: "auto",
  proxy_url: "socks5://127.0.0.1:9050",
  proxy_enabled: false,
  proxy_preset: "tor",
  close_to_tray: false,
  opsec_mode: false,
  opsec_window_title: "Notes",
  opsec_view_timeout_secs: 30,
};

/** Prefix of the `update_settings` error when only the armor comment was dropped. */
const ARMOR_COMMENT_REJECTED = "Couldn't save the armor comment";

function settingsErrorText(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error && error.message) return error.message;
  return String(error);
}

let settings: Settings = $state({ ...defaults });
let loaded: boolean = $state(false);

export const settingsStore = {
  get settings() {
    return settings;
  },
  get loaded() {
    return loaded;
  },

  async load() {
    try {
      settings = await getSettings();
    } catch {
      settings = { ...defaults };
    }
    loaded = true;
  },

  async save(partial: Partial<Settings>) {
    const previous = settings;
    const next: Settings = { ...settings, ...partial };
    if (partial.armor_comment !== undefined) {
      next.armor_comment = partial.armor_comment.trim();
    }
    settings = next;
    try {
      await updateSettings(next);
    } catch (error) {
      console.error("Failed to save settings:", error);
      const message = settingsErrorText(error);
      if (message.includes(ARMOR_COMMENT_REJECTED)) {
        // The other fields were written and the comment was replaced with the
        // last safe value. Reload so the rejected text cannot fail later saves.
        try {
          settings = await getSettings();
        } catch {
          settings = previous;
        }
      } else {
        settings = previous;
      }
      appStore.setStatus(message);
    }
  },
};
