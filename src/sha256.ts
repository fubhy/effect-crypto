import { sha256 as rawSha256 } from "@noble/hashes/sha256"
import type { Input } from "@noble/hashes/utils"
import { Effect } from "effect"

export const sha256 = (input: Input) => Effect.succeed(rawSha256(input))
