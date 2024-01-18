/**
 * @since 1.0.0
 */

import * as NobleArgon2 from "@noble/hashes/argon2"
import * as NobleBlake2b from "@noble/hashes/blake2b"
import * as NobleBlake2s from "@noble/hashes/blake2s"
import * as NobleBlake3 from "@noble/hashes/blake3"
import * as NobleScrypt from "@noble/hashes/scrypt"
import * as NobleSha256 from "@noble/hashes/sha256"
import * as NobleSha512 from "@noble/hashes/sha512"
import * as Data from "effect/Data"
import * as Either from "effect/Either"
import * as Predicate from "effect/Predicate"

/**
 * @since 1.0.0
 * @category errors
 */
export class CryptoError extends Data.TaggedError("effect-crypto/CryptoError")<{
  cause: unknown
}> {}

/**
 * Returns `true` if the specified value is an `CryptoError`, `false` otherwise.
 *
 * @since 1.0.0
 * @category refinements
 */
export const isCryptoError: (error: unknown) => error is CryptoError = Predicate.isTagged(
  "effect-crypto/CryptoError"
) as any

/**
 * Internal helper function to wrap an encoder utility with `Either.try`.
 */
const wrap =
  <T extends (...args: Array<any>) => any>(fn: T) =>
  (...args: Parameters<T>): Either.Either<CryptoError, ReturnType<T>> =>
    Either.try({
      try: () => fn(...args),
      catch: (cause) => new CryptoError({ cause })
    })

/**
 * Hashes the input with SHA-224.
 *
 * @since 1.0.0
 * @category hashing
 */
export const sha224: (input: string | Uint8Array) => Uint8Array = NobleSha256.sha224

/**
 * Hashes the input with SHA-256.
 *
 * @since 1.0.0
 * @category hashing
 */
export const sha256: (input: string | Uint8Array) => Uint8Array = NobleSha256.sha256

/**
 * Hashes the input with SHA-384.
 *
 * @since 1.0.0
 * @category hashing
 */
export const sha384: (input: string | Uint8Array) => Uint8Array = NobleSha512.sha384

/**
 * Hashes the input with SHA-512.
 *
 * @since 1.0.0
 * @category hashing
 */
export const sha512: (input: string | Uint8Array) => Uint8Array = NobleSha512.sha512

/**
 * Hashes the input with SHA-512/224.
 *
 * @since 1.0.0
 * @category hashing
 */
export const sha512_224: (input: string | Uint8Array) => Uint8Array = NobleSha512.sha512_224

/**
 * Hashes the input with SHA-512/256.
 *
 * @since 1.0.0
 * @category hashing
 */
export const sha512_256: (input: string | Uint8Array) => Uint8Array = NobleSha512.sha512_256

/**
 * Password hashing the password and salt with scrypt.
 *
 * @since 1.0.0
 * @category password hashing
 */
export const scrypt: (
  input: string | Uint8Array,
  salt: string | Uint8Array,
  options: NobleScrypt.ScryptOpts
) => Either.Either<CryptoError, Uint8Array> = wrap(NobleScrypt.scrypt)

/**
 * Password hashing the password and salt with argon2d.
 *
 * @since 1.0.0
 * @category password hashing
 */
export const argon2d: (
  password: Uint8Array | string,
  salt: Uint8Array | string,
  opts: NobleArgon2.ArgonOpts
) => Either.Either<CryptoError, Uint8Array> = wrap(NobleArgon2.argon2d)

/**
 * Password hashing the password and salt with argon2i.
 *
 * @since 1.0.0
 * @category password hashing
 */
export const argon2i: (
  password: Uint8Array | string,
  salt: Uint8Array | string,
  opts: NobleArgon2.ArgonOpts
) => Either.Either<CryptoError, Uint8Array> = wrap(NobleArgon2.argon2i)

/**
 * Password hashing the password and salt with argon2id.
 *
 * @since 1.0.0
 * @category password hashing
 */
export const argon2id: (
  password: Uint8Array | string,
  salt: Uint8Array | string,
  opts: NobleArgon2.ArgonOpts
) => Either.Either<CryptoError, Uint8Array> = wrap(NobleArgon2.argon2id)

/**
 * TODO: This is not strictly modeled in `@noble/hashes/blake3`.
 */
type Blake3Opts = {
  dkLen?: number
  key: Uint8Array | string
  context?: never
} | {
  dkLen?: number
  key?: never
  context: Uint8Array | string
} | {
  dkLen?: number
  key?: never
  context?: never
}

/**
 * Hashes the input with blake3.
 *
 * @since 1.0.0
 * @category hashing
 */
export const blake3: (
  input: Uint8Array | string,
  opts?: Blake3Opts | undefined
) => Either.Either<CryptoError, Uint8Array> = wrap(NobleBlake3.blake3)

/**
 * TODO: This is not exported by `@noble/hashes/blake2s`.
 */
type Blake2sOpts = Parameters<typeof NobleBlake2s.blake2s>[1]

/**
 * Hashes the input with blake2.
 *
 * @since 1.0.0
 * @category hashing
 */
export const blake2s: (
  input: Uint8Array | string,
  opts?: Blake2sOpts | undefined
) => Either.Either<CryptoError, Uint8Array> = wrap(NobleBlake2s.blake2s)

/**
 * TODO: This is not exported by `@noble/hashes/blake2b`.
 */
type Blake2bOpts = Parameters<typeof NobleBlake2b.blake2b>[1]

/**
 * Hashes the input with blake2b.
 *
 * @since 1.0.0
 * @category hashing
 */
export const blake2b: (
  input: Uint8Array | string,
  opts?: Blake2bOpts | undefined
) => Either.Either<CryptoError, Uint8Array> = wrap(NobleBlake2b.blake2b)
