/**
 * Append an ASCII-armored public key so it travels inside the encrypted
 * plaintext. A blank line separates the message from the key. If the message
 * already ends with that same key, it is not added again.
 */
export function appendPublicKey(message: string, armoredKey: string): string {
  const key = armoredKey.trim();
  if (!key) return message;
  const body = message.replace(/[ \t\r\n]+$/u, "");
  if (!body) return `${key}\n`;
  if (body.endsWith(key)) return `${body}\n`;
  return `${body}\n\n${key}\n`;
}
