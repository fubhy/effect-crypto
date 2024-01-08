import * as Scrypt from "@noble/hashes/scrypt"
import * as Data from "effect/Data"
import * as Effect from "effect/Effect"

class ScryptOptionsError extends Data.Error<{ message: string }> {}

export const scrypt = (input: string | Uint8Array, salt: string | Uint8Array, options: Scrypt.ScryptOpts) =>
  Effect.try({
    try: () => Scrypt.scrypt(input, salt, options),
    catch: (error) =>
      error instanceof Error ? new ScryptOptionsError(error) : new ScryptOptionsError({ message: "Unknown error" })
  })
