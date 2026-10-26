import { getLocale } from "$lib/paraglide/runtime.js";
import * as m from "$lib/paraglide/messages.js";

/** Format a full fingerprint as grouped hex: "ABCD 1234 ..." */
export function formatFingerprint(fp: string): string {
  return fp.replace(/(.{4})/g, "$1 ").trim();
}

/** Short fingerprint: last 8 chars. */
export function shortFingerprint(fp: string): string {
  return fp.slice(-8).toUpperCase();
}

/** Format an ISO 8601 date string to a readable date. */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return m.date_na();
  const date = new Date(iso);
  if (isNaN(date.getTime())) return iso.split("T")[0] ?? iso;
  return date.toLocaleDateString(getLocale(), {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

type LabeledKey = {
  alias?: string | null;
  name?: string | null;
  email?: string | null;
};

/** Local alias, then the certificate name, then the unnamed fallback. */
export function keyLabel(key: LabeledKey): string {
  const alias = key.alias?.trim();
  if (alias) return alias;
  const name = key.name?.trim();
  if (name) return name;
  return m.unnamed();
}

/** Certificate name to show when a different alias is the title. */
export function keyCertificateName(key: LabeledKey): string | null {
  const alias = key.alias?.trim();
  const name = key.name?.trim();
  if (alias && name && alias !== name) return name;
  return null;
}

/** Secondary line: certificate name ahead of the email when an alias is set. */
export function keySecondary(key: LabeledKey, fallback: string): string {
  const certificateName = keyCertificateName(key);
  const email = key.email?.trim();
  if (certificateName && email) return `${certificateName} · ${email}`;
  if (certificateName) return certificateName;
  if (email) return email;
  return fallback;
}

/** Truncate text to maxLen, appending "..." if truncated. */
export function truncate(text: string, maxLen: number): string {
  if (text.length <= maxLen) return text;
  return text.slice(0, maxLen) + "...";
}

/** Check if text looks like a PGP message. */
export function isPgpMessage(text: string): boolean {
  return text.trimStart().startsWith("-----BEGIN PGP MESSAGE-----");
}

/** Check if text looks like a PGP signed message. */
export function isPgpSignedMessage(text: string): boolean {
  return text.trimStart().startsWith("-----BEGIN PGP SIGNED MESSAGE-----");
}

/** Check if text looks like a PGP public key. */
export function isPgpPublicKey(text: string): boolean {
  return text.trimStart().startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----");
}
