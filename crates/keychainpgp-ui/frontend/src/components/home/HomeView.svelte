<script lang="ts">
  import { Lock, Unlock, PenLine, ShieldCheck, Clipboard, MessageSquare } from "lucide-svelte";
  import ClipboardPreview from "./ClipboardPreview.svelte";
  import ComposeInput from "./ComposeInput.svelte";
  import Kbd from "../shared/Kbd.svelte";
  import { appStore } from "$lib/stores/app.svelte";
  import { clipboardStore } from "$lib/stores/clipboard.svelte";
  import { keyStore } from "$lib/stores/keys.svelte";
  import { isPgpMessage } from "$lib/utils";
  import { isDesktop } from "$lib/platform";
  import { decryptText, signText, verifyText, writeClipboard } from "$lib/tauri";
  import * as m from "$lib/paraglide/messages.js";

  let isCompose = $derived(appStore.inputMode === "compose");
  const desktop = isDesktop();

  /**
   * Snapshot the compose field or clipboard, then freeze clipboard polling.
   * `release()` (or a dialog's `onDismiss`) resumes polling. The snapshot is
   * the text this action read, not `clipboardStore.content`: a poll can
   * supersede that read and then be dropped by the hold, or publish a later
   * clipboard value first. Without the freeze, copying a passphrase replaces
   * the message being encrypted, decrypted, or signed.
   */
  async function takeInput(): Promise<{
    text: string | null;
    compose: boolean;
    release: () => void;
  }> {
    const compose = isCompose;
    if (compose) {
      return {
        compose,
        text: appStore.composeText || null,
        release() {},
      };
    }
    const text = await clipboardStore.refresh();
    clipboardStore.hold(text);
    let released = false;
    return {
      compose,
      text,
      release() {
        if (released) return;
        released = true;
        clipboardStore.release();
      },
    };
  }

  // React to external actions (hotkeys, tray)
  $effect(() => {
    const action = appStore.pendingAction;
    if (!action) return;
    appStore.clearAction();
    switch (action) {
      case "encrypt":
        handleEncrypt();
        break;
      case "decrypt":
        handleDecrypt();
        break;
      case "sign":
        handleSign();
        break;
      case "verify":
        handleVerify();
        break;
    }
  });

  async function handleEncrypt() {
    const { text, compose, release } = await takeInput();
    if (!text) {
      release();
      appStore.setStatus(compose ? m.encrypt_empty_compose() : m.encrypt_empty_clipboard());
      return;
    }
    if (keyStore.keys.length === 0) {
      release();
      appStore.setStatus(m.encrypt_no_keys());
      return;
    }
    appStore.openModal("recipient-selector", { text, onDismiss: release });
  }

  async function handleDecrypt() {
    const { text, compose, release } = await takeInput();
    let handoff = false;
    try {
      if (!text) {
        appStore.setStatus(compose ? m.decrypt_empty_compose() : m.decrypt_empty_clipboard());
        return;
      }
      if (!isPgpMessage(text)) {
        appStore.setStatus(m.decrypt_no_pgp());
        return;
      }
      appStore.setStatus(m.decrypt_in_progress(), 0);
      try {
        const result = await decryptText(text);
        if (result.success) {
          appStore.openModal("decrypted-viewer", { plaintext: result.plaintext });
          appStore.setStatus(m.decrypt_success());
          clipboardStore.scheduleAutoClear();
        } else {
          appStore.setStatus(result.message);
        }
      } catch (e) {
        const msg = String(e);
        if (msg.includes("passphrase") || msg.includes("private key")) {
          handoff = true;
          appStore.openModal("passphrase", {
            onDismiss: release,
            onSubmit: async (passphrase: string) => {
              try {
                const result = await decryptText(text, passphrase);
                if (result.success) {
                  appStore.openModal("decrypted-viewer", { plaintext: result.plaintext });
                  appStore.setStatus(m.decrypt_success());
                  clipboardStore.scheduleAutoClear();
                } else {
                  appStore.openModal("error", { error: result.message });
                }
              } catch (e2) {
                appStore.openModal("error", { error: String(e2) });
              } finally {
                release();
              }
            },
          });
        } else {
          appStore.openModal("error", { error: msg, suggestion: m.decrypt_wrong_key_hint() });
        }
      }
    } finally {
      if (!handoff) release();
    }
  }

  async function handleSign() {
    const { text, compose, release } = await takeInput();
    if (!text) {
      release();
      appStore.setStatus(compose ? m.sign_empty_compose() : m.sign_empty_clipboard());
      return;
    }
    if (!keyStore.hasOwnKey) {
      release();
      appStore.setStatus(m.sign_no_key());
      return;
    }
    const message = text;
    appStore.setStatus(m.sign_in_progress(), 0);

    async function doSign(passphrase?: string) {
      const result = await signText(message, passphrase);
      if (!result.success) {
        appStore.openModal("error", { error: result.message });
        return;
      }
      if (compose) {
        appStore.composeText = result.message;
      } else {
        await writeClipboard(result.message);
      }
      appStore.setStatus(m.sign_success_compose());
      appStore.closeModal();
    }

    try {
      await doSign();
      release();
    } catch (e) {
      const msg = String(e);
      if (msg.includes("passphrase")) {
        appStore.openModal("passphrase", {
          onDismiss: release,
          onSubmit: async (passphrase: string) => {
            try {
              await doSign(passphrase);
            } catch (e2) {
              appStore.openModal("error", { error: String(e2) });
            } finally {
              release();
            }
          },
        });
      } else {
        release();
        appStore.openModal("error", { error: msg });
      }
    }
  }

  async function handleVerify() {
    const { text, compose, release } = await takeInput();
    try {
      if (!text) {
        appStore.setStatus(compose ? m.verify_empty_compose() : m.verify_empty_clipboard());
        return;
      }
      appStore.setStatus(m.verify_in_progress(), 0);
      const result = await verifyText(text);
      appStore.openModal("verify-result", { verifyResult: result });
      appStore.setStatus(result.valid ? m.verify_success() : m.verify_failed());
    } catch (e) {
      appStore.openModal("error", { error: String(e) });
    } finally {
      release();
    }
  }
</script>

<div
  class="mx-auto max-w-2xl space-y-6"
  class:flex={!desktop}
  class:flex-col={!desktop}
  class:h-full={!desktop}
>
  {#if desktop}
    <div class="space-y-2 text-center">
      <h1 class="text-2xl font-bold">{m.home_title()}</h1>
      <p class="text-[var(--color-text-secondary)]">
        {isCompose ? m.home_tagline_compose() : m.home_tagline_clipboard()}
      </p>
    </div>
  {:else}
    <div class="flex items-center gap-3">
      <img src="/logo-32.png" alt="KeychainPGP" class="h-8 w-8 rounded-lg" />
      <div>
        <h1 class="text-xl font-bold">{m.home_title()}</h1>
        <p class="text-sm text-[var(--color-text-secondary)]">
          {isCompose ? m.home_tagline_compose() : m.home_tagline_clipboard()}
        </p>
      </div>
    </div>
  {/if}

  <!-- Input mode toggle (desktop only — mobile always uses compose) -->
  {#if desktop}
    <div class="flex justify-center">
      <div class="inline-flex rounded-lg border border-[var(--color-border)] p-0.5">
        <button
          class="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm transition-colors"
          class:bg-[var(--color-primary)]={!isCompose}
          class:text-white={!isCompose}
          onclick={() => (appStore.inputMode = "clipboard")}
        >
          <Clipboard size={14} />
          {m.mode_clipboard()}
        </button>
        <button
          class="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm transition-colors"
          class:bg-[var(--color-primary)]={isCompose}
          class:text-white={isCompose}
          onclick={() => (appStore.inputMode = "compose")}
        >
          <MessageSquare size={14} />
          {m.mode_compose()}
        </button>
      </div>
    </div>
  {/if}

  {#if isCompose}
    <div class:flex-1={!desktop} class:min-h-0={!desktop}>
      <ComposeInput mobile={!desktop} />
    </div>
  {:else}
    <ClipboardPreview />
  {/if}

  <div
    class="mx-auto grid w-full max-w-md grid-cols-2"
    class:mt-auto={!desktop}
    class:gap-2={!desktop}
    class:gap-3={desktop}
  >
    <button
      class="flex flex-col items-center rounded-lg
             bg-[var(--color-primary)] font-semibold
             text-white transition-colors hover:bg-[var(--color-primary-hover)]"
      class:py-4={desktop}
      class:py-2.5={!desktop}
      class:gap-1={desktop}
      class:gap-0.5={!desktop}
      class:text-sm={!desktop}
      onclick={handleEncrypt}
    >
      <Lock size={desktop ? 20 : 18} />
      {m.action_encrypt()}
      {#if desktop}<Kbd keys={[m.kbd_ctrl(), m.kbd_shift(), "E"]} variant="light" />{/if}
    </button>
    <button
      class="flex flex-col items-center rounded-lg
             bg-[var(--color-primary)] font-semibold
             text-white transition-colors hover:bg-[var(--color-primary-hover)]"
      class:py-4={desktop}
      class:py-2.5={!desktop}
      class:gap-1={desktop}
      class:gap-0.5={!desktop}
      class:text-sm={!desktop}
      onclick={handleDecrypt}
    >
      <Unlock size={desktop ? 20 : 18} />
      {m.action_decrypt()}
      {#if desktop}<Kbd keys={[m.kbd_ctrl(), m.kbd_shift(), "D"]} variant="light" />{/if}
    </button>
    <button
      class="flex flex-col items-center rounded-lg border-2
             border-[var(--color-primary)] font-semibold text-[var(--color-primary)]
             transition-colors hover:bg-[var(--color-primary)] hover:text-white"
      class:py-4={desktop}
      class:py-2.5={!desktop}
      class:gap-1={desktop}
      class:gap-0.5={!desktop}
      class:text-sm={!desktop}
      onclick={handleSign}
    >
      <PenLine size={desktop ? 20 : 18} />
      {m.action_sign()}
      {#if desktop}<Kbd keys={[m.kbd_ctrl(), m.kbd_shift(), "S"]} />{/if}
    </button>
    <button
      class="flex flex-col items-center rounded-lg border-2
             border-[var(--color-primary)] font-semibold text-[var(--color-primary)]
             transition-colors hover:bg-[var(--color-primary)] hover:text-white"
      class:py-4={desktop}
      class:py-2.5={!desktop}
      class:gap-1={desktop}
      class:gap-0.5={!desktop}
      class:text-sm={!desktop}
      onclick={handleVerify}
    >
      <ShieldCheck size={desktop ? 20 : 18} />
      {m.action_verify()}
      {#if desktop}<Kbd keys={[m.kbd_ctrl(), m.kbd_shift(), "V"]} />{/if}
    </button>
  </div>
</div>
