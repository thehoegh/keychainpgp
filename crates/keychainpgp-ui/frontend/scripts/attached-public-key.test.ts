/**
 * Run: node --experimental-strip-types --test scripts/attached-public-key.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { attachedPublicKey, isPgpPublicKey } from "../src/lib/public-key.ts";

const PUBLIC_KEY =
  "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc\n-----END PGP PUBLIC KEY BLOCK-----";
const PRIVATE_KEY =
  "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nsecret\n-----END PGP PRIVATE KEY BLOCK-----";

test("a public key block is attachable", () => {
  assert.equal(isPgpPublicKey(PUBLIC_KEY), true);
  assert.equal(attachedPublicKey(PUBLIC_KEY), PUBLIC_KEY);
});

test("a prefix check would accept a following private key block", () => {
  const combined = `${PUBLIC_KEY}\n${PRIVATE_KEY}\n`;
  assert.equal(combined.trimStart().startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"), true);
  assert.equal(isPgpPublicKey(combined), false);
});

test("attached public key drops a following private key block", () => {
  const combined = `${PUBLIC_KEY}\n${PRIVATE_KEY}\n`;
  const attached = attachedPublicKey(combined);
  assert.equal(attached, PUBLIC_KEY);
  assert.equal(attached?.includes("PRIVATE KEY BLOCK"), false);
  assert.equal(attached?.includes("secret"), false);
});

test("a private key block before the public key is not attached", () => {
  const combined = `${PRIVATE_KEY}\n${PUBLIC_KEY}\n`;
  const attached = attachedPublicKey(combined);
  assert.equal(attached, PUBLIC_KEY);
  assert.equal(attached?.includes("PRIVATE KEY BLOCK"), false);
});

test("an unclosed private key block is not attached", () => {
  const combined = `${PUBLIC_KEY}\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nsecret without end`;
  const attached = attachedPublicKey(combined);
  assert.equal(attached, PUBLIC_KEY);
  assert.equal(attached?.includes("secret"), false);
});

test("a private key alone cannot be attached", () => {
  assert.equal(isPgpPublicKey(PRIVATE_KEY), false);
  assert.equal(attachedPublicKey(PRIVATE_KEY), null);
});
