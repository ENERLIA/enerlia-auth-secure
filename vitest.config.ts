import { defineConfig } from "vitest/config";

export default defineConfig({
  // Les tests de bout en bout enchaînent des dizaines de connexions : chacune calcule
  // une empreinte de mot de passe, volontairement lente. 5 s ne suffit pas sur la CI.
  test: { include: ["tests/**/*.test.ts"], environment: "node", testTimeout: 30_000 },
});
