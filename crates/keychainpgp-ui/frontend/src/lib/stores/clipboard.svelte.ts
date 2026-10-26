import { readClipboard, clearClipboard } from "$lib/tauri";
import { isPgpMessage, isPgpSignedMessage } from "$lib/utils";
import {
  beginClipboardRead,
  createClipboardReads,
  finishClipboardRead,
  holdClipboardRead,
  releaseClipboardRead,
} from "./clipboard-generation";
import { settingsStore } from "./settings.svelte";

let content: string | null = $state(null);
let pollInterval: ReturnType<typeof setInterval> | null = null;
let autoClearTimer: ReturnType<typeof setTimeout> | null = null;
let polling = false;
/** See `clipboard-generation.ts` for why a stale read may still publish. */
const reads = createClipboardReads();

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

  /**
   * Read the clipboard. Returns the text this call observed.
   * Publishes it only when no newer read has published and the snapshot
   * is not held. Callers that are about to `hold()` must use the return
   * value: a poll can both supersede this read and then be dropped.
   */
  async refresh(): Promise<string | null> {
    const seq = beginClipboardRead(reads);
    if (seq === null) return content;
    let next: string | null;
    try {
      next = await readClipboard();
    } catch {
      next = null;
    }
    if (finishClipboardRead(reads, seq)) content = next;
    return next;
  },

  /**
   * Pin `snapshot` until `release()`. In-flight polls cannot replace it,
   * so copying a passphrase does not replace the message.
   */
  hold(snapshot: string | null) {
    holdClipboardRead(reads);
    content = snapshot;
  },

  release() {
    if (!releaseClipboardRead(reads)) return;
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
