import { getDefaultSession, originOf } from '../core/redact.ts';
import type { Vault } from '../core/redact.ts';

/** Messages carry the token and the selector, never the value. */
export class FillError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FillError';
  }
}

export const TOKEN_RE = /^\[[A-Z_]+_\d+\]$/;

/** The part of a Playwright ElementHandle the executor needs. */
export interface FillHandle {
  evaluate<R>(fn: (el: { ownerDocument: { location: { origin: string } } }) => R): Promise<R>;
  fill(value: string, options?: { timeout?: number }): Promise<void>;
}

/** The part of a Playwright Page the executor needs. Elements come from the main frame only. */
export interface Fillable {
  url(): string;
  mainFrame(): {
    waitForSelector(selector: string, options: { state: 'attached'; timeout: number }): Promise<FillHandle | null>;
  };
}

export const DEFAULT_TIMEOUT_MS = 2000;

// Playwright selector engines and pseudo-classes that can leave the main frame, match by text or
// by position, or run XPath. Only plain CSS is accepted.
const ENGINE_PREFIX = /^\s*[A-Za-z][\w-]*\s*=/;
const FORBIDDEN = [
  />>/,
  /internal:/i,
  /aria-ref/i,
  /\/\//,
  /^\s*\.\.?(\/|\s*$)/,
  /:(?:text|has-text|text-is|text-matches|visible|nth-match|above|below|near|left-of|right-of|light)\b/i,
];

export function isPlainCssSelector(selector: string): boolean {
  if (typeof selector !== 'string' || selector.trim().length === 0 || selector.length > 500) return false;
  if (ENGINE_PREFIX.test(selector)) return false;
  return !FORBIDDEN.some((re) => re.test(selector));
}

/**
 * The only place where a vault value is read, and only on the origin the value came from.
 * The element is looked up in the main frame with a short timeout, its own document's origin
 * is checked, and the value goes in through that same element handle: if the page navigates in
 * between, the handle is detached and the fill fails. The value is not returned or logged.
 */
export async function fill(
  page: Fillable,
  selector: string,
  token: string,
  vault: Vault = getDefaultSession().vault,
  options: { timeout?: number } = {},
): Promise<void> {
  if (typeof selector !== 'string' || selector.length === 0) throw new FillError('fill needs a selector');
  if (!isPlainCssSelector(selector)) throw new FillError('selector not allowed: use a plain CSS selector');
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) throw new FillError('fill needs a placeholder like [CARD_1]');
  const value = vault.get(token);
  if (value === undefined) throw new FillError(`unknown token ${token}`);
  const bound = vault.originOf(token);
  if (bound === undefined) throw new FillError(`token ${token} has no origin binding`);
  if (originOf(page.url()) !== bound) throw new FillError(`token ${token} may not be filled on this page`);
  const timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
  let handle: FillHandle | null;
  try {
    handle = await page.mainFrame().waitForSelector(selector, { state: 'attached', timeout });
  } catch {
    throw new FillError(`fill failed for ${token} on ${selector}`);
  }
  if (!handle) throw new FillError(`fill failed for ${token} on ${selector}`);
  let elementOrigin: string | undefined;
  try {
    elementOrigin = await handle.evaluate((el) => el.ownerDocument.location.origin);
  } catch {
    throw new FillError(`fill failed for ${token} on ${selector}`);
  }
  if (elementOrigin !== bound) throw new FillError(`token ${token} may not be filled in this document`);
  try {
    await handle.fill(value, { timeout });
  } catch {
    // the underlying error is dropped on purpose: it may echo what was typed
    throw new FillError(`fill failed for ${token} on ${selector}`);
  }
}
