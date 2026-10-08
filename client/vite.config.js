import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

const target = process.env.VITE_PROXY || 'http://localhost:8080';
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: { '/api': target, '/v1': target } },
});
