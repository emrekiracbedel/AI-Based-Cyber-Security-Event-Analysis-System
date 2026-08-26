import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const port = Number.parseInt(process.env.DEV_SERVER_PORT ?? "5173", 10);

export default defineConfig({
  plugins: [react()],
  base: "./",
  server: {
    port: Number.isFinite(port) ? port : 5173,
    strictPort: true,
    host: "127.0.0.1",
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: true },
      "/ws": { target: "ws://127.0.0.1:8000", ws: true },
    },
  },
});
