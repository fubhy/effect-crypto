import * as NobleSha256 from "@noble/hashes/sha256"
import * as NobleSha512 from "@noble/hashes/sha512"

export const sha224 = (input: string | Uint8Array) => NobleSha256.sha224(input)
export const sha256 = (input: string | Uint8Array) => NobleSha256.sha256(input)
export const sha384 = (input: string | Uint8Array) => NobleSha512.sha384(input)
export const sha512 = (input: string | Uint8Array) => NobleSha512.sha512(input)
export const sha512_224 = (input: string | Uint8Array) => NobleSha512.sha512_224(input)
export const sha512_256 = (input: string | Uint8Array) => NobleSha512.sha512_256(input)
