import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/session.ts", "src/tentatives.ts", "src/mot-de-passe.ts", "src/envois-email.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  target: "es2022",
  external: ["better-auth"],
});
