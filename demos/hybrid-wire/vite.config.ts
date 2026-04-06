import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-hybrid-wire/',
  test: {
    environment: 'node',
    include: ['src/__tests__/**/*.test.ts'],
  },
});
