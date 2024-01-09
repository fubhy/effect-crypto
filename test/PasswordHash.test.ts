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

it("should fail with `ScryptOptionsError`", () => {
  const output = Crypto.scrypt("password", "salt", { N: 123, r: 8, p: 1, dkLen: 32 })
  expect(Either.isLeft(output)).toBe(true)
  expect(Either.getLeft(output)).toMatchObject(Option.some({
    _tag: "ScryptOptionsError",
    cause: new Error(
      "Scrypt: N must be larger than 1, a power of 2, less than 2^(128 * r / 8) and less than 2^32"
    )
  }))
})
