import { Either } from "effect"
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
