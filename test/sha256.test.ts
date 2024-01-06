import { Effect } from "effect"
import { sha256 } from "effect-crypto/sha256"
import { expect, it } from "vitest"

it(`should successfully hash a string`, () => {
  expect(Effect.runSync(sha256("Test"))).toStrictEqual(
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
