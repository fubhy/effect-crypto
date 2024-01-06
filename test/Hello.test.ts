import * as Hello from "effect-crypto/Hello"
import { expect, it } from "vitest"

it(`should say "Hello" to everyone`, () => {
  expect(Hello.say("World")).toBe("Hello World!")
})

it(`should say "Hello" to Nik`, () => {
  expect(Hello.say("Nik")).toBe("Servas Nik!")
})
