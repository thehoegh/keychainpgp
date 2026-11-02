<script lang="ts">
  import { Lock, PenLine, RefreshCw } from "lucide-svelte";
  import { clipboardStore } from "$lib/stores/clipboard.svelte";
  import { truncate } from "$lib/utils";
  import * as m from "$lib/paraglide/messages.js";
</script>

<div
  class="relative flex min-h-32 flex-col rounded-lg border border-[var(--color-border)] bg-[var(--color-bg-secondary)] p-4"
>
  <div class="mb-2 flex items-center justify-between">
    <span class="text-xs font-medium tracking-wide text-[var(--color-text-secondary)] uppercase">
      {m.clipboard_label()}
    </span>
    <div class="flex items-center gap-2">
      {#if clipboardStore.isSignedMessage}
        <span class="inline-flex items-center gap-1 text-xs font-medium text-green-600">
          <PenLine size={12} />
          {m.clipboard_signed_message()}
        </span>
      {:else if clipboardStore.isPgpMessage}
        <span
          class="inline-flex items-center gap-1 text-xs font-medium text-[var(--color-primary)]"
        >
          <Lock size={12} />
          {m.clipboard_pgp_message()}
        </span>
      {/if}
      <button
        class="rounded p-1 transition-colors hover:bg-[var(--color-border)]"
        onclick={() => clipboardStore.refresh()}
        title={m.clipboard_refresh()}
      >
        <RefreshCw size={14} class="text-[var(--color-text-secondary)]" />
      </button>
    </div>
  </div>

  <div
    class="max-h-60 min-h-24 w-full overflow-y-auto font-mono text-sm break-all whitespace-pre-wrap"
  >
    {#if clipboardStore.content}
      <p class="text-[var(--color-text)]">
        {truncate(clipboardStore.content, 500)}
      </p>
    {:else}
      <p class="text-[var(--color-text-secondary)]">
        {m.clipboard_empty()}
      </p>
    {/if}
  </div>
</div>
