/**
 * @since 1.0.0
 */

import * as Scrypt from "@noble/hashes/scrypt"
import * as NobleSha256 from "@noble/hashes/sha256"
import * as NobleSha512 from "@noble/hashes/sha512"
import * as Data from "effect/Data"
import * as Either from "effect/Either"
import * as Predicate from "effect/Predicate"

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

class ScryptOptionsError extends Data.TaggedError("ScryptOptionsError")<{
  cause: unknown
}> {}

/**
 * Returns `true` if the specified value is an `ScryptOptionsError`, `false` otherwise.
 *
 * @since 2.0.0
 * @category refinements
 */
export const isScryptOptionsError: (error: unknown) => error is ScryptOptionsError = Predicate.isTagged(
  "ScryptOptionsError"
) as any

/**
 * Password hashing the password and salt with scrypt.
 *
 * @since 1.0.0
 * @category password hashing
 */
export const scrypt = (
  input: string | Uint8Array,
  salt: string | Uint8Array,
  options: Scrypt.ScryptOpts
): Either.Either<ScryptOptionsError, Uint8Array> =>
  Either.try({
    try: () => Scrypt.scrypt(input, salt, options),
    catch: (cause) => new ScryptOptionsError({ cause })
  })
