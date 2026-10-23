import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests/e2e', timeout: 60000, workers: 1, fullyParallel: false,
  use: { baseURL: 'http://localhost:3100', browserName: 'chromium', launchOptions: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH, args: ['--no-sandbox'] } : {}, trace: 'retain-on-failure' },
  webServer: { command: 'npm run dev', url: 'http://localhost:3100/api/config', timeout: 120000, reuseExistingServer: false, env: { PORT: '3100', PUBLIC_ORIGIN: 'http://localhost:3100', RP_ID: 'localhost', DATA_DIR: 'memory://', NODE_ENV: 'test' } },
});
