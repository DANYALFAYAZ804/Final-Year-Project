import { defineConfig } from 'vite';

// https://vitejs.dev/config
export default defineConfig({
  build: {
    rollupOptions: {
      external: [
        'electron',
        'path',
        'fs',
        'child_process',
        'http',
        'https',
        'os',
        'crypto',
        'url',
        'util',
        'stream',
        'events',
        'buffer',
        'node:url',
        'node:path',
        'node:fs',
        'node:http',
        'node:https',
        'node:child_process',
      ],
    },
  },
});
