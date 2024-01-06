/**
 * @since 1.0.0
 */

import * as hash from "./internal/hash.js"

/**
 * Hashes the input with SHA-224.
 *
 * @since 1.0.0
 * @category hashing
 */
export const sha224: (input: string | Uint8Array) => Uint8Array = hash.sha224

/**
 * Hashes the input with SHA-256.
 *
 * @since 1.0.0
 * @category hashing
 */
export const sha256: (input: string | Uint8Array) => Uint8Array = hash.sha256

/**
 * Hashes the input with SHA-384.
 *
 * @since 1.0.0
 * @category hashing
 */
export const sha384: (input: string | Uint8Array) => Uint8Array = hash.sha384

/**
 * Hashes the input with SHA-512.
 *
 * @since 1.0.0
 * @category hashing
 */
export const sha512: (input: string | Uint8Array) => Uint8Array = hash.sha512

/**
 * Hashes the input with SHA-512/224.
 *
 * @since 1.0.0
 * @category hashing
 */
export const sha512_224: (input: string | Uint8Array) => Uint8Array = hash.sha512_224

/**
 * Hashes the input with SHA-512/256.
 *
 * @since 1.0.0
 * @category hashing
 */
export const sha512_256: (input: string | Uint8Array) => Uint8Array = hash.sha512_256
