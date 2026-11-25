/**
 * Run: node --experimental-strip-types --test scripts/append-public-key.test.ts
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { appendPublicKey } from "../src/lib/append-public-key.ts";

const KEY = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc\n-----END PGP PUBLIC KEY BLOCK-----";

test("appends the key after a blank line", () => {
  assert.equal(appendPublicKey("hello", KEY), `hello\n\n${KEY}\n`);
});

test("trims trailing whitespace on the message and the key", () => {
  assert.equal(appendPublicKey("hello\n\n", `  ${KEY}\n`), `hello\n\n${KEY}\n`);
});

test("does not append the same key twice", () => {
  const once = appendPublicKey("hello", KEY);
  assert.equal(appendPublicKey(once, KEY), once);
});

test("returns the message unchanged when the key is empty", () => {
  assert.equal(appendPublicKey("hello", "  \n"), "hello");
});
