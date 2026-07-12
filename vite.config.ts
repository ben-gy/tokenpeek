import { defineConfig } from 'vite';
import { VitePWA } from 'vite-plugin-pwa';

// Custom domain — tokenpeek.benrichardson.dev — so base is '/'.
export default defineConfig({
  base: '/',
  plugins: [
    VitePWA({
      registerType: 'autoUpdate',
      includeAssets: ['favicon.svg'],
      manifest: {
        name: 'tokenpeek — offline JWT toolkit',
        short_name: 'tokenpeek',
        description:
          'Decode, inspect, verify, crack and forge JSON Web Tokens entirely in your browser.',
        theme_color: '#0a0e17',
        background_color: '#0a0e17',
        display: 'standalone',
        icons: [
          {
            src: 'favicon.svg',
            sizes: 'any',
            type: 'image/svg+xml',
            purpose: 'any',
          },
        ],
      },
    }),
  ],
  build: {
    target: 'es2022',
    sourcemap: true,
  },
  worker: {
    format: 'es',
  },
  server: {
    port: 5173,
    strictPort: false,
  },
  test: {
    environment: 'jsdom',
    globals: true,
  },
});
