import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    allowedHosts: true,
    hmr: false,
    proxy: {
      '/mask': {
        target: 'http://api:5002',
        changeOrigin: true,
        timeout: 600000,
        proxyTimeout: 600000,
      }
    }
  }
})
