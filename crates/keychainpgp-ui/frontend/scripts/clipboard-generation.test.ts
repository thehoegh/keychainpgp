/**
 * Run: node --experimental-strip-types --test scripts/clipboard-generation.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  beginClipboardRead,
  createClipboardReads,
  finishClipboardRead,
  holdClipboardRead,
  releaseClipboardRead,
} from "../src/lib/stores/clipboard-generation.ts";

/**
 * Same publication steps as `clipboardStore.refresh` / `hold`.
 * `content` stays in the store so Svelte sees the assignment.
 */
function createHarness(initial: string | null) {
  let content: string | null = initial;
  const reads = createClipboardReads();

  return {
    get content() {
      return content;
    },
    start(): number | null {
      return beginClipboardRead(reads);
    },
    finish(seq: number, next: string | null): string | null {
      if (finishClipboardRead(reads, seq)) content = next;
      return next;
    },
    hold(snapshot?: string | null) {
      holdClipboardRead(reads);
      if (snapshot !== undefined) content = snapshot;
    },
    release(): boolean {
      return releaseClipboardRead(reads);
    },
  };
}

test("a single read publishes the clipboard text", () => {
  const clipboard = createHarness("stale");
  const seq = clipboard.start();
  assert.ok(seq !== null);
  assert.equal(clipboard.finish(seq, "message"), "message");
  assert.equal(clipboard.content, "message");
});

test("hold does not drop both the action read and the poll that superseded it", () => {
  const clipboard = createHarness("stale");
  const actionSeq = clipboard.start();
  const pollSeq = clipboard.start();
  assert.ok(actionSeq !== null && pollSeq !== null);
  assert.ok(pollSeq > actionSeq);

  // The action finishes first. The poll is newer but has not published.
  const observed = clipboard.finish(actionSeq, "message");
  clipboard.hold(observed);
  // The poll read the passphrase copied while the action read was in flight.
  clipboard.finish(pollSeq, "passphrase");

  assert.equal(observed, "message");
  assert.equal(clipboard.content, "message");
});

test("a poll that finishes first does not keep the passphrase over the action read", () => {
  const clipboard = createHarness("stale");
  const actionSeq = clipboard.start();
  const pollSeq = clipboard.start();
  assert.ok(actionSeq !== null && pollSeq !== null);

  clipboard.finish(pollSeq, "passphrase");
  const observed = clipboard.finish(actionSeq, "message");
  clipboard.hold(observed);

  assert.equal(observed, "message");
  assert.equal(clipboard.content, "message");
});

test("a newer read still replaces an older one when the snapshot is not held", () => {
  const clipboard = createHarness("stale");
  const older = clipboard.start();
  const newer = clipboard.start();
  assert.ok(older !== null && newer !== null);

  clipboard.finish(older, "old");
  clipboard.finish(newer, "new");

  assert.equal(clipboard.content, "new");
});

test("an older read does not overwrite a newer read that already published", () => {
  const clipboard = createHarness("stale");
  const older = clipboard.start();
  const newer = clipboard.start();
  assert.ok(older !== null && newer !== null);

  clipboard.finish(newer, "new");
  clipboard.finish(older, "old");

  assert.equal(clipboard.content, "new");
});

test("a held snapshot ignores new reads until release", () => {
  const clipboard = createHarness("message");
  clipboard.hold("message");

  assert.equal(clipboard.start(), null);
  clipboard.release();

  const seq = clipboard.start();
  assert.ok(seq !== null);
  clipboard.finish(seq, "after");
  assert.equal(clipboard.content, "after");
});

test("an in-flight read cannot publish after release", () => {
  const clipboard = createHarness("stale");
  const actionSeq = clipboard.start();
  const pollSeq = clipboard.start();
  assert.ok(actionSeq !== null && pollSeq !== null);

  clipboard.finish(actionSeq, "message");
  clipboard.hold("message");
  assert.equal(clipboard.release(), true);
  clipboard.finish(pollSeq, "passphrase");

  assert.equal(clipboard.content, "message");
});
