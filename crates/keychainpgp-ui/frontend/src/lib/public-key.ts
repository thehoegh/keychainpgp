const PUBLIC_KEY_BEGIN = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const PUBLIC_KEY_END = "-----END PGP PUBLIC KEY BLOCK-----";
const PRIVATE_KEY_BEGIN = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
const PRIVATE_KEY_END = "-----END PGP PRIVATE KEY BLOCK-----";

/**
 * True when `text` is a public key block and does not also contain a private
 * key block. A combined file starts with the public header, so a prefix check
 * is not enough.
 */
export function isPgpPublicKey(text: string): boolean {
  const trimmed = text.trim();
  return (
    trimmed.startsWith(PUBLIC_KEY_BEGIN) &&
    trimmed.includes(PUBLIC_KEY_END) &&
    !trimmed.includes(PRIVATE_KEY_BEGIN)
  );
}

/**
 * Public key armor to append to a message.
 *
 * Private key blocks are removed. Returns null when no complete public key
 * block remains.
 */
export function attachedPublicKey(text: string): string | null {
  const candidate = splitPgpKeyBlocks(text).publicKeys.trim();
  if (!isPgpPublicKey(candidate)) return null;
  return candidate;
}

function splitPgpKeyBlocks(text: string): { publicKeys: string; privateKeys: string } {
  let publicKeys = "";
  let privateKeys = "";
  let current = "";
  let mode: "public" | "private" | null = null;

  for (const line of linesWithEndings(text)) {
    const label = line.replace(/[\r\n]+$/u, "").trim();
    if (mode === null) {
      if (label === PUBLIC_KEY_BEGIN) {
        mode = "public";
        current = line;
      } else if (label === PRIVATE_KEY_BEGIN) {
        mode = "private";
        current = line;
      }
      continue;
    }

    current += line;
    if (mode === "public" && label === PUBLIC_KEY_END) {
      publicKeys = appendBlock(publicKeys, current);
      current = "";
      mode = null;
    } else if (mode === "private" && label === PRIVATE_KEY_END) {
      privateKeys = appendBlock(privateKeys, current);
      current = "";
      mode = null;
    }
  }

  // Keep an unclosed private key block out of the public key.
  if (mode === "private" && current) {
    privateKeys = appendBlock(privateKeys, current);
  }

  return { publicKeys, privateKeys };
}

function appendBlock(output: string, block: string): string {
  if (!output) return block;
  return output.endsWith("\n") ? output + block : `${output}\n${block}`;
}

function linesWithEndings(text: string): string[] {
  const lines: string[] = [];
  let rest = text;
  while (rest.length > 0) {
    const index = rest.indexOf("\n");
    if (index === -1) {
      lines.push(rest);
      break;
    }
    lines.push(rest.slice(0, index + 1));
    rest = rest.slice(index + 1);
  }
  return lines;
}
