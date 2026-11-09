import { existsSync } from 'node:fs';
import { chromium } from 'playwright-core';
import type { Browser } from 'playwright-core';

const CANDIDATES = [
  '/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
];

/**
 * Starts a private headless Chrome with a throwaway profile (no browser download).
 * Order: env CF_CHROME_PATH, a known local install, then the `chrome` channel.
 */
export async function launchChrome(): Promise<Browser> {
  const explicit = process.env.CF_CHROME_PATH;
  const executablePath = explicit || CANDIDATES.find((p) => existsSync(p));
  return executablePath ? chromium.launch({ executablePath, headless: true }) : chromium.launch({ channel: 'chrome', headless: true });
}
