import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// GitHub Pages 配下 (https://<user>.github.io/tls-demo/) で動くよう base を設定。
// ローカル開発では "/" を使う。
// テストは vitest の既定 (node 環境) で動くため、ここに test 設定は置かない
// (vite と vitest が参照する vite のバージョン差による型衝突を避ける)。
export default defineConfig(({ command }) => ({
  base: command === "build" ? "/tls-demo/" : "/",
  plugins: [react(), tailwindcss()],
}));
