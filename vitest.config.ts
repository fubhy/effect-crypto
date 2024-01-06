import * as path from "node:path"
import { defineConfig } from "vitest/config"

export default defineConfig({
  test: {
    include: ["./test/**/*.test.ts"],
    sequence: {
      concurrent: true
    },
    alias: {
      "effect-crypto/test": path.join(__dirname, "test"),
      "effect-crypto": path.join(__dirname, "src")
    }
  }
})
