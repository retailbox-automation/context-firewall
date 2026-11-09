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

/** A Playwright Frame: the executor reads only its URL, which Playwright tracks outside the page. */
export interface FillFrame {
  url(): string;
}

/** The part of a Playwright ElementHandle the executor needs. */
export interface FillHandle {
  ownerFrame(): Promise<FillFrame | null>;
  evaluate(fn: (el: any, arg: string) => void, arg: string): Promise<void>;
}

/** The part of a Playwright Page the executor needs. Elements come from the main frame only. */
export interface Fillable {
  url(): string;
  mainFrame(): FillFrame & {
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
 * Runs inside the page, on the element handle only: native value setter, then input and change
 * events. No focus, no keyboard: nothing depends on which element happens to hold the focus.
 */
function setValueInPage(el: any, value: string): void {
  const g = globalThis as any;
  const proto = el.tagName === 'TEXTAREA' ? g.HTMLTextAreaElement.prototype : el.tagName === 'INPUT' ? g.HTMLInputElement.prototype : null;
  if (!proto) throw new Error('not a text field');
  Object.getOwnPropertyDescriptor(proto, 'value')!.set!.call(el, value);
  el.dispatchEvent(new g.Event('input', { bubbles: true }));
  el.dispatchEvent(new g.Event('change', { bubbles: true }));
}

/**
 * The only place where a vault value is read, and only on the origin the value came from.
 * The element is looked up in the main frame with a short timeout. Its origin is read from
 * Playwright's own record of the frame that owns it (never from script running in the page, which
 * the page can replace), and must equal the bound origin; the main frame's URL is checked again
 * right before the value is written. The write is one evaluate on that same handle: a detached
 * handle or a destroyed context makes it throw and nothing is typed. The URL is checked once more
 * afterwards and a move is reported in the error (the value cannot be taken back, but the fact is
 * not hidden). The value is not returned or logged.
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
  if (vault.isAmbiguous(token)) throw new FillError(`token ${token}: ambiguous card run, not filled`);
  const bound = vault.originOf(token);
  if (bound === undefined) throw new FillError(`token ${token} has no origin binding`);
  if (originOf(page.url()) !== bound) throw new FillError(`token ${token} may not be filled on this page`);
  const timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
  const failed = new FillError(`fill failed for ${token} on ${selector}`);
  const main = page.mainFrame();
  let handle: FillHandle | null;
  let owner: FillFrame | null;
  try {
    handle = await main.waitForSelector(selector, { state: 'attached', timeout });
    owner = handle ? await handle.ownerFrame() : null;
  } catch {
    throw failed;
  }
  if (!handle || !owner) throw failed;
  if (owner !== main || originOf(owner.url()) !== bound) throw new FillError(`token ${token} may not be filled in this document`);
  if (originOf(page.mainFrame().url()) !== bound) throw new FillError(`token ${token} may not be filled on this page`);
  try {
    await handle.evaluate(setValueInPage, value);
  } catch {
    // the underlying error is dropped on purpose: it may echo what was typed
    throw failed;
  }
  if (originOf(page.mainFrame().url()) !== bound) {
    throw new FillError(`token ${token}: the page moved while the value was being written`);
  }
}
