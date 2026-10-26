import { readClipboard, clearClipboard } from "$lib/tauri";
import { isPgpMessage, isPgpSignedMessage } from "$lib/utils";
import { settingsStore } from "./settings.svelte";

let content: string | null = $state(null);
let pollInterval: ReturnType<typeof setInterval> | null = null;
let autoClearTimer: ReturnType<typeof setTimeout> | null = null;
/** While true, polls keep running but must not replace `content`. */
let held = false;
let polling = false;
let refreshSeq = 0;

export const clipboardStore = {
  get content() {
    return content;
  },

  get isPgpMessage() {
    return content ? isPgpMessage(content) : false;
  },

  get isSignedMessage() {
    return content ? isPgpSignedMessage(content) : false;
  },

  async refresh() {
    if (held) return;
    const seq = ++refreshSeq;
    try {
      const next = await readClipboard();
      // A passphrase copy can land while this read is in flight. Drop it
      // so it cannot replace the message captured for encrypt/decrypt/sign.
      if (seq !== refreshSeq || held) return;
      content = next;
    } catch {
      if (seq !== refreshSeq || held) return;
      content = null;
    }
  },

  /**
   * Keep the current clipboard snapshot. Idempotent. Pair with `release()`.
   * Used while a passphrase or recipient dialog is open, so copying a
   * passphrase does not replace the message.
   */
  hold() {
    held = true;
  },

  release() {
    if (!held) return;
    held = false;
    if (polling) void this.refresh();
  },

  startPolling(intervalMs = 2000) {
    this.stopPolling();
    polling = true;
    void this.refresh();
    pollInterval = setInterval(() => {
      void this.refresh();
    }, intervalMs);
  },

  stopPolling() {
    polling = false;
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
  },

  /** Schedule clipboard auto-clear after decrypt/encrypt. OPSEC forces 10s. */
  scheduleAutoClear() {
    if (autoClearTimer) {
      clearTimeout(autoClearTimer);
      autoClearTimer = null;
    }

    const s = settingsStore.settings;
    const isOpsec = s.opsec_mode;

    // In OPSEC mode: always clear after 10s. Otherwise: use user setting.
    if (!isOpsec && !s.auto_clear_enabled) return;

    const delaySecs = isOpsec ? 10 : s.auto_clear_delay_secs;

    autoClearTimer = setTimeout(async () => {
      try {
        await clearClipboard();
      } catch {
        // ignore
      }
      autoClearTimer = null;
    }, delaySecs * 1000);
  },
};
