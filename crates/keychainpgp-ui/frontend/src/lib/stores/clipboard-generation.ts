/**
 * Orders clipboard reads against a held snapshot.
 *
 * A poll or a second click can start a newer read before an earlier one
 * finishes. If the earlier read is dropped for being stale and the newer
 * read is then dropped because the snapshot is held, the published text
 * never changes. A finished read still publishes when no newer read has
 * published yet and the snapshot is not held.
 */
export interface ClipboardReads {
  held: boolean;
  /** Generation of the latest read that has started, or of a pin. */
  started: number;
  /** Generation of the latest read or pin that owns the published text. */
  published: number;
}

export function createClipboardReads(): ClipboardReads {
  return { held: false, started: 0, published: 0 };
}

/** Start a read. Returns its generation, or null when the snapshot is held. */
export function beginClipboardRead(reads: ClipboardReads): number | null {
  if (reads.held) return null;
  reads.started += 1;
  return reads.started;
}

/**
 * Finish a read. True when this result should replace the published text.
 * The caller keeps the text this read observed either way.
 */
export function finishClipboardRead(reads: ClipboardReads, seq: number): boolean {
  if (reads.held || reads.published >= seq) return false;
  reads.published = seq;
  return true;
}

/**
 * Pin the published text. In-flight reads have an older generation, so they
 * cannot publish over the pin — including after `releaseClipboardRead()`.
 */
export function holdClipboardRead(reads: ClipboardReads): void {
  reads.held = true;
  reads.started += 1;
  reads.published = reads.started;
}

/** Resume reads. Returns false when nothing was held. */
export function releaseClipboardRead(reads: ClipboardReads): boolean {
  if (!reads.held) return false;
  reads.held = false;
  return true;
}
