<script lang="ts">
  import { KeyRound, Lock, PenLine, X } from "lucide-svelte";
  import { appStore } from "$lib/stores/app.svelte";
  import { keyStore } from "$lib/stores/keys.svelte";
  import type { KeyInfo } from "$lib/tauri";
  import { isPgpMessage, isPgpSignedMessage, keyLabel, shortFingerprint } from "$lib/utils";
  import * as m from "$lib/paraglide/messages.js";

  let { mobile = false }: { mobile?: boolean } = $props();

  let pgpMessage = $derived(appStore.composeText ? isPgpMessage(appStore.composeText) : false);
  let signedMessage = $derived(
    appStore.composeText ? isPgpSignedMessage(appStore.composeText) : false,
  );
  let attachableOwn = $derived(keyStore.ownKeys.filter((k) => !k.is_revoked));
  let attachableContacts = $derived(keyStore.contactKeys.filter((k) => !k.is_revoked));
  let hasAttachableKeys = $derived(attachableOwn.length > 0 || attachableContacts.length > 0);

  // Drop a selection whose key was deleted or revoked. Skip while a refresh
  // is in flight so a transient empty list does not clear the choice.
  $effect(() => {
    const fp = appStore.composeAttachedFingerprint;
    if (!fp || keyStore.loading) return;
    const available = keyStore.keys.some((k) => k.fingerprint === fp && !k.is_revoked);
    if (!available) appStore.composeAttachedFingerprint = null;
  });

  function attachOptionLabel(key: KeyInfo): string {
    return `${keyLabel(key)} · ${shortFingerprint(key.fingerprint)}`;
  }

  function handleAttachChange(e: Event) {
    const value = (e.currentTarget as HTMLSelectElement).value;
    appStore.composeAttachedFingerprint = value || null;
  }
</script>

<div
  class="relative flex flex-col rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4"
  class:min-h-32={!mobile}
  class:h-full={mobile}
>
  <div class="mb-2 flex items-center justify-between">
    <span class="text-xs font-medium tracking-wide text-[var(--color-text-secondary)] uppercase">
      {m.compose_label()}
    </span>
    <div class="flex items-center gap-2">
      {#if signedMessage}
        <span class="inline-flex items-center gap-1 text-xs font-medium text-green-600">
          <PenLine size={12} />
          {m.clipboard_signed_message()}
        </span>
      {:else if pgpMessage}
        <span
          class="inline-flex items-center gap-1 text-xs font-medium text-[var(--color-primary)]"
        >
          <Lock size={12} />
          {m.clipboard_pgp_message()}
        </span>
      {/if}
      {#if appStore.composeText}
        <button
          class="rounded p-1 transition-colors hover:bg-[var(--color-border)]"
          onclick={() => (appStore.composeText = "")}
          title={m.compose_clear()}
        >
          <X size={14} class="text-[var(--color-text-secondary)]" />
        </button>
      {/if}
    </div>
  </div>

  <textarea
    class="w-full bg-transparent font-mono text-sm
           text-[var(--color-text)] placeholder-[var(--color-text-secondary)]
           focus:outline-none"
    class:min-h-24={!mobile}
    class:max-h-60={!mobile}
    class:resize-y={!mobile}
    class:flex-1={mobile}
    class:resize-none={mobile}
    placeholder={m.compose_placeholder()}
    bind:value={appStore.composeText}
  ></textarea>

  {#if hasAttachableKeys}
    <div class="mt-3 flex flex-col gap-1.5 border-t border-[var(--color-border)] pt-3">
      <div class="flex flex-wrap items-center gap-2">
        <label
          for="compose-attach-key"
          class="inline-flex shrink-0 items-center gap-1 text-xs font-medium text-[var(--color-text-secondary)]"
        >
          <KeyRound size={12} />
          {m.compose_attach_key()}
        </label>
        <select
          id="compose-attach-key"
          class="min-w-0 flex-1 rounded border border-[var(--color-border)] bg-[var(--color-bg)] px-2 py-1 text-xs
                 focus:ring-2 focus:ring-[var(--color-primary)] focus:outline-none"
          value={appStore.composeAttachedFingerprint ?? ""}
          onchange={handleAttachChange}
        >
          <option value="">{m.compose_attach_none()}</option>
          {#if attachableOwn.length > 0}
            <optgroup label={m.keys_section_own()}>
              {#each attachableOwn as key (key.fingerprint)}
                <option value={key.fingerprint}>{attachOptionLabel(key)}</option>
              {/each}
            </optgroup>
          {/if}
          {#if attachableContacts.length > 0}
            <optgroup label={m.keys_section_contacts()}>
              {#each attachableContacts as key (key.fingerprint)}
                <option value={key.fingerprint}>{attachOptionLabel(key)}</option>
              {/each}
            </optgroup>
          {/if}
        </select>
      </div>
      {#if appStore.composeAttachedFingerprint}
        <p class="text-xs text-[var(--color-text-secondary)]">{m.compose_attach_hint()}</p>
      {/if}
    </div>
  {/if}
</div>
