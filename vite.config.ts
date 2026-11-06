import { defineConfig } from 'vitest/config'

export default defineConfig({
  // Pre-bundle the browser harness's dependencies at server start. Otherwise
  // Vite discovers them on first import and reloads the page, which destroys
  // the Playwright evaluation context mid-test.
  optimizeDeps: {
    entries: ['test/browser/harness.ts']
  },
  test: {
    include: ['test/node/**/*.test.ts', 'src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.ts']
    }
  }
})
