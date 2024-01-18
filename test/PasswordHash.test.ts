import { Either, Option } from "effect"
import * as Crypto from "effect-crypto"
import { expect, it } from "vitest"

it("should successfully use scrypt", () => {
  expect(Crypto.scrypt("password", "salt", { N: 2 ** 16, r: 8, p: 1, dkLen: 32 })).toStrictEqual(
    Either.right(
      new Uint8Array([
        249,
        20,
        156,
        172,
        159,
        169,
        36,
        9,
        104,
        163,
        144,
        69,
        72,
        30,
        58,
        146,
        29,
        11,
        233,
        197,
        112,
        22,
        217,
        25,
        216,
        41,
        77,
        10,
        51,
        250,
        50,
        18
      ])
    )
  )
})

it("should fail with `effect-crypto/CryptoError` for scrypt", () => {
  const output = Crypto.scrypt("password", "salt", { N: 123, r: 8, p: 1, dkLen: 32 })
  expect(Either.isLeft(output)).toBe(true)
  expect(Either.getLeft(output)).toMatchObject(Option.some({
    _tag: "effect-crypto/CryptoError",
    cause: new Error(
      "Scrypt: N must be larger than 1, a power of 2, less than 2^(128 * r / 8) and less than 2^32"
    )
  }))
})

it("should successfully use argon2d", () => {
  expect(Crypto.argon2d("password", "longer_salt", { t: 2, m: 65536, p: 1 })).toStrictEqual(
    Either.right(
      new Uint8Array([
        25,
        228,
        174,
        160,
        123,
        201,
        45,
        45,
        82,
        161,
        91,
        94,
        150,
        160,
        97,
        227,
        129,
        154,
        173,
        3,
        254,
        158,
        245,
        200,
        7,
        212,
        3,
        150,
        4,
        254,
        160,
        3
      ])
    )
  )
})

it("should fail with `effect-crypto/CryptoError` for argon2d", () => {
  const output = Crypto.argon2d("password", "salt", { t: 2, m: 65536, p: 1 })
  expect(Either.isLeft(output)).toBe(true)
  expect(Either.getLeft(output)).toMatchObject(Option.some({
    _tag: "effect-crypto/CryptoError",
    cause: new Error(
      "Argon2: salt should be at least 8 bytes"
    )
  }))
})

it("should successfully use argon2i", () => {
  expect(Crypto.argon2i("password", "longer_salt", { t: 2, m: 65536, p: 1 })).toStrictEqual(
    Either.right(
      new Uint8Array([
        144,
        243,
        154,
        244,
        118,
        16,
        62,
        34,
        8,
        106,
        241,
        63,
        147,
        94,
        17,
        208,
        11,
        89,
        203,
        10,
        230,
        38,
        203,
        172,
        27,
        32,
        0,
        198,
        30,
        147,
        201,
        82
      ])
    )
  )
})

it("should fail with `effect-crypto/CryptoError` for argon2i", () => {
  const output = Crypto.argon2i("password", "salt", { t: 2, m: 65536, p: 1 })
  expect(Either.isLeft(output)).toBe(true)
  expect(Either.getLeft(output)).toMatchObject(Option.some({
    _tag: "effect-crypto/CryptoError",
    cause: new Error(
      "Argon2: salt should be at least 8 bytes"
    )
  }))
})

it("should successfully use argon2id", () => {
  expect(Crypto.argon2id("password", "longer_salt", { t: 2, m: 65536, p: 1 })).toStrictEqual(
    Either.right(
      new Uint8Array([
        209,
        64,
        171,
        201,
        208,
        162,
        239,
        97,
        242,
        73,
        250,
        187,
        92,
        96,
        154,
        104,
        242,
        228,
        56,
        31,
        60,
        164,
        109,
        249,
        187,
        56,
        153,
        42,
        206,
        222,
        81,
        173
      ])
    )
  )
})

it("should fail with `effect-crypto/CryptoError` for argon2id", () => {
  const output = Crypto.argon2id("password", "salt", { t: 2, m: 65536, p: 1 })
  expect(Either.isLeft(output)).toBe(true)
  expect(Either.getLeft(output)).toMatchObject(Option.some({
    _tag: "effect-crypto/CryptoError",
    cause: new Error(
      "Argon2: salt should be at least 8 bytes"
    )
  }))
})
