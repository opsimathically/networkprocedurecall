import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["cjs", "esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  external: [
    "./transpilers/swc.js",
    "source-map-support",
    "@cspotcode/source-map-support",
  ], // Mark it external
});
