import { Either, Option } from "effect"
import * as Crypto from "effect-crypto"
import { expect, it } from "vitest"

it("should successfully hash a string using SHA-256", () => {
  expect(Crypto.sha256("Test")).toStrictEqual(
    new Uint8Array([
      83,
      46,
      170,
      189,
      149,
      116,
      136,
      13,
      191,
      118,
      185,
      184,
      204,
      0,
      131,
      44,
      32,
      166,
      236,
      17,
      61,
      104,
      34,
      153,
      85,
      13,
      122,
      110,
      15,
      52,
      94,
      37
    ])
  )
})

it("should successfully use blake2b", () => {
  expect(Crypto.blake2b("hello_world")).toStrictEqual(
    Either.right(
      new Uint8Array([
        128,
        39,
        193,
        124,
        27,
        21,
        70,
        168,
        81,
        236,
        166,
        10,
        9,
        65,
        145,
        138,
        155,
        24,
        172,
        94,
        30,
        237,
        56,
        253,
        137,
        88,
        16,
        208,
        218,
        149,
        53,
        240,
        49,
        109,
        192,
        213,
        61,
        161,
        219,
        42,
        68,
        61,
        83,
        193,
        242,
        141,
        3,
        89,
        10,
        158,
        162,
        145,
        246,
        131,
        100,
        12,
        211,
        196,
        48,
        81,
        19,
        227,
        112,
        177
      ])
    )
  )
})

it("should fail with `effect-crypto/CryptoError` for blake2b", () => {
  const output = Crypto.blake2b("hello_world", { key: new Uint8Array([1]), personalization: "a", salt: "b", dkLen: 32 })
  expect(Either.isLeft(output)).toBe(true)
  expect(Either.getLeft(output)).toMatchObject(Option.some({
    _tag: "effect-crypto/CryptoError",
    cause: new Error(
      "salt must be 16 byte long or undefined"
    )
  }))
})

it("should successfully use blake2s", () => {
  expect(Crypto.blake2s("hello_world")).toStrictEqual(
    Either.right(
      new Uint8Array([
        51,
        69,
        200,
        159,
        88,
        136,
        134,
        3,
        252,
        7,
        170,
        17,
        43,
        96,
        154,
        76,
        135,
        183,
        166,
        224,
        132,
        226,
        38,
        76,
        208,
        93,
        211,
        26,
        45,
        201,
        82,
        58
      ])
    )
  )
})

it("should fail with `effect-crypto/CryptoError` for blake2b", () => {
  const output = Crypto.blake2s("hello_world", { key: new Uint8Array([1]), personalization: "a", salt: "b", dkLen: 32 })
  expect(Either.isLeft(output)).toBe(true)
  expect(Either.getLeft(output)).toMatchObject(Option.some({
    _tag: "effect-crypto/CryptoError",
    cause: new Error(
      "salt must be 8 byte long or undefined"
    )
  }))
})

it("should successfully use blake3", () => {
  expect(Crypto.blake3("hello_world")).toStrictEqual(
    Either.right(
      new Uint8Array([
        152,
        51,
        229,
        50,
        78,
        178,
        64,
        13,
        232,
        20,
        115,
        15,
        78,
        146,
        129,
        9,
        5,
        53,
        27,
        192,
        69,
        30,
        16,
        183,
        88,
        71,
        33,
        12,
        29,
        124,
        55,
        237
      ])
    )
  )
})

it("should fail with `effect-crypto/CryptoError` for blake3", () => {
  // @ts-expect-error
  const output = Crypto.blake3("hello_world", { dkLen: 256, key: "def", context: "fji" })
  expect(Either.isLeft(output)).toBe(true)
  expect(Either.getLeft(output)).toMatchObject(Option.some({
    _tag: "effect-crypto/CryptoError",
    cause: new Error(
      "Blake3: only key or context can be specified at same time"
    )
  }))
})
