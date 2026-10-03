import { defineConfig } from "vite";

export default defineConfig({
  build: {
    outDir: "web-dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    strictPort: true,
    watch: {
      ignored: ["**/src-tauri/**", "**/target/**"],
    },
  },
});
