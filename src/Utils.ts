/**
 * @since 1.0.0
 */

import * as NobleCiphers from "@noble/ciphers/utils"
import * as NobleHashes from "@noble/hashes/utils"
import * as Data from "effect/Data"
import * as Either from "effect/Either"
import * as Predicate from "effect/Predicate"

/**
 * An error thrown when an error occurs in the `Utils` module.
 *
 * @since 1.0.0
 * @category errors
 */
export class UtilsError extends Data.TaggedError("effect-crypto/UtilsError")<{
  cause: unknown
}> {}

/**
 * Returns `true` if the specified value is an `UtilsError`, `false` otherwise.
 *
 * @since 1.0.0
 * @category refinements
 */
export const isUtilsError: (error: unknown) => error is UtilsError = Predicate.isTagged(
  "effect-crypto/UtilsError"
) as any

/**
 * Internal helper function to wrap an encoder utility with `Either.try`.
 */
const wrap =
  <T extends (...args: Array<any>) => any>(fn: T) =>
  (...args: Parameters<T>): Either.Either<UtilsError, ReturnType<T>> =>
    Either.try({
      try: () => fn(...args),
      catch: (cause) => new UtilsError({ cause })
    })

/**
 * Converts a hex `string` to a `Uint8Array`.
 *
 * @since 1.0.0
 * @category encoding
 */
export const bytesToHex: (
  bytes: Uint8Array
) => Either.Either<UtilsError, string> = wrap(NobleCiphers.bytesToHex)

/**
 * Converts a `Uint8Array` to a hex `string`.
 *
 * @since 1.0.0
 * @category encoding
 */
export const hexToBytes: (
  hex: string
) => Either.Either<UtilsError, Uint8Array> = wrap(NobleCiphers.hexToBytes)

/**
 * Converts a `Uint8Array` to a `string`.
 *
 * @since 1.0.0
 * @category encoding
 */
export const bytesToUtf8: (input: Uint8Array) => string = NobleCiphers.bytesToUtf8

/**
 * Converts a `string` to a `Uint8Array`.
 *
 * @since 1.0.0
 * @category encoding
 */
export const utf8ToBytes: (input: string) => Uint8Array = NobleCiphers.utf8ToBytes

/**
 * Converts a `number` to a `Uint8Array`.
 *
 * @since 1.0.0
 * @category encoding
 */
export const numberToBytes: (
  value: number | bigint,
  length: number
) => Either.Either<UtilsError, Uint8Array> = wrap(NobleCiphers.numberToBytesBE)

/**
 * Converts a `Uint8Array` to a `number`.
 *
 * @since 1.0.0
 * @category encoding
 */
export const bytesToNumber: (
  bytes: Uint8Array
) => Either.Either<UtilsError, bigint> = wrap(NobleCiphers.bytesToNumberBE)

/**
 * Concatenates multiple `Uint8Array`s into a single `Uint8Array`.
 *
 * This is a more efficient version of `Uint8Array.from([...arrays].flat())`.
 *
 * @since 1.0.0
 * @category encoding
 */
export const concatBytes: (...arrays: Array<Uint8Array>) => Uint8Array = NobleCiphers.concatBytes

/**
 * Returns a `Uint8Array` of the specified length filled with random bytes.
 *
 * This uses `crypto.getRandomValues` and may throw an error if the underlying
 * implementation is not available.
 *
 * @since 1.0.0
 * @category random
 */
export const randomBytes: (length?: number) => Uint8Array = NobleHashes.randomBytes
