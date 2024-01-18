/**
 * @since 1.0.0
 */

import * as CiphersUtils from "@noble/ciphers/utils"
import * as HashUtils from "@noble/hashes/utils"
import * as Data from "effect/Data"
import * as Either from "effect/Either"
import * as Predicate from "effect/Predicate"

const utilsError = "effect-crypto/UtilsError"

/**
 * An error thrown when an error occurs in the `Utils` module.
 *
 * @since 1.0.0
 * @category errors
 */
export class UtilsError extends Data.TaggedError(utilsError)<{ cause: unknown }> {}

/**
 * Returns `true` if the specified value is an `UtilsError`, `false` otherwise.
 *
 * @since 1.0.0
 * @category refinements
 */
export const isUtilsError: (error: unknown) => error is UtilsError = Predicate.isTagged(utilsError) as any

/**
 * Internal helper function to wrap an encoder utility with `Either.try`.
 */
const makeEncoder =
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
) => Either.Either<UtilsError, string> = makeEncoder(CiphersUtils.bytesToHex)

/**
 * Converts a `Uint8Array` to a hex `string`.
 *
 * @since 1.0.0
 * @category encoding
 */
export const hexToBytes: (
  hex: string
) => Either.Either<UtilsError, Uint8Array> = makeEncoder(CiphersUtils.hexToBytes)

/**
 * Converts a `string` to a `Uint8Array`.
 *
 * @since 1.0.0
 * @category encoding
 */
export const utf8ToBytes: (input: string) => Uint8Array = CiphersUtils.utf8ToBytes

/**
 * Converts a `number` to a `Uint8Array`.
 *
 * @since 1.0.0
 * @category encoding
 */
export const numberToBytes: (
  value: number | bigint,
  length: number
) => Either.Either<UtilsError, Uint8Array> = makeEncoder(CiphersUtils.numberToBytesBE)

/**
 * Converts a `Uint8Array` to a `number`.
 *
 * @since 1.0.0
 * @category encoding
 */
export const bytesToNumber: (bytes: Uint8Array) => Either.Either<UtilsError, bigint> = makeEncoder(
  CiphersUtils.bytesToNumberBE
)

/**
 * Concatenates multiple `Uint8Array`s into a single `Uint8Array`.
 *
 * This is a more efficient version of `Uint8Array.from([...arrays].flat())`.
 *
 * @since 1.0.0
 * @category encoding
 */
export const concatBytes: (...arrays: Array<Uint8Array>) => Uint8Array = CiphersUtils.concatBytes

/**
 * Returns a `Uint8Array` of the specified length filled with random bytes.
 *
 * This uses `crypto.getRandomValues` and may throw an error if the underlying
 * implementation is not available.
 *
 * @since 1.0.0
 * @category random
 */
export const randomBytes: (length?: number) => Uint8Array = HashUtils.randomBytes
