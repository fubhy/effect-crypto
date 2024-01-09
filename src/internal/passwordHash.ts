import * as Scrypt from "@noble/hashes/scrypt"
import * as Data from "effect/Data"
import * as Effect from "effect/Effect"

class OptionsError extends Data.TaggedError("OptionsError")<{
  cause: unknown
}> {}

export const scrypt = (input: string | Uint8Array, salt: string | Uint8Array, options: Scrypt.ScryptOpts) =>
  Effect.try({
    try: () => Scrypt.scrypt(input, salt, options),
    catch: (cause) => new OptionsError({ cause })
  })
