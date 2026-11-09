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

/** The part of a Playwright Page the executor needs. */
export interface Fillable {
  url(): string;
  fill(selector: string, value: string, options?: { timeout?: number }): Promise<void>;
}

/**
 * The only place where a vault value is read, and only on the origin the value came from. The value goes straight into the page;
 * it is not returned, logged, or put into an error.
 */
export async function fill(
  page: Fillable,
  selector: string,
  token: string,
  vault: Vault = getDefaultSession().vault,
  options: { timeout?: number } = {},
): Promise<void> {
  if (typeof selector !== 'string' || selector.length === 0) throw new FillError('fill needs a selector');
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) throw new FillError('fill needs a placeholder like [CARD_1]');
  const value = vault.get(token);
  if (value === undefined) throw new FillError(`unknown token ${token}`);
  const bound = vault.originOf(token);
  if (bound === undefined) throw new FillError(`token ${token} has no origin binding`);
  if (originOf(page.url()) !== bound) throw new FillError(`token ${token} may not be filled on this page`);
  try {
    await page.fill(selector, value, options);
  } catch {
    // the underlying error is dropped on purpose: it may echo what was typed
    throw new FillError(`fill failed for ${token} on ${selector}`);
  }
}
