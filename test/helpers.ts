import type { Fillable } from '../src/executor/fill.ts';

// Test values are assembled from parts so the source holds no secret-shaped literal.
export const j = (...parts: string[]): string => parts.join('');

export const VISA = j('4111', '1111', '1111', '1111');
export const VISA_SPACED = ['4111', '1111', '1111', '1111'].join(' ');
export const VISA_DASHED = ['4111', '1111', '1111', '1111'].join('-');
export const MASTERCARD = j('5555', '5555', '5555', '4444');
export const MC_2SERIES = j('2223', '0031', '2200', '3222');
export const AMEX = j('3782', '822463', '10005');
export const DISCOVER = j('6011', '1111', '1111', '1117');
export const JCB = j('3530', '1113', '3330', '0000');
export const UNIONPAY = j('6200', '0000', '0000', '0005');
export const LUHN_BAD = j('4111', '1111', '1111', '1112');
export const LUHN_OK_UNKNOWN_IIN = j('9111', '1111', '1111', '1115');

export const SSN = ['123', '45', '6789'].join('-');
export const ITIN = ['912', '70', '1234'].join('-');
export const EIN = ['12', '3456789'].join('-');
export const IBAN_DE = j('DE89', ' 3704', ' 0044', ' 0532', ' 0130', ' 00');

export const AWS_ID = j('AK', 'IA', 'ABCDEFGHIJKLMNOP');
export const AWS_SECRET = j('wJalrXUtnFEMI', '/K7MDENG/', 'bPxRfiCYEXAMPLEKEY');
export const OPENAI = j('sk', '-proj-', 'Ab3dEfGh1jKlMnOp2qRsTuVw4xYz');
export const ANTHROPIC = j('sk', '-ant-', 'Ab3dEfGh1jKlMnOp2qRsTuVw4xYz');
export const GITHUB = j('gh', 'p_', 'Ab3dEfGh1jKlMnOp2qRsTuVw4xYz5678abcd');
export const STRIPE = j('sk', '_live_', 'Ab3dEfGh1jKlMnOp2qRsTuVw');
export const SLACK = j('xox', 'b-', '1234567890-1234567890123-', 'AbCdEfGhIjKlMnOpQrStUvWx');
export const GOOGLE = j('AI', 'za', 'Ab3dEfGh1jKlMnOp2qRsTuVw4xYz56789_-');
export const PEM = [j('-----BEGIN ', 'PRIVATE KEY-----'), 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC', 'KgwggSkAgEAAoIBAQC7VJTUt9Us8cKj', j('-----END ', 'PRIVATE KEY-----')].join('\n');
const b64 = (o: object): string => Buffer.from(JSON.stringify(o)).toString('base64url');
export const JWT = [b64({ alg: 'HS256', typ: 'JWT' }), b64({ sub: 'u1' }), 'c2lnbmF0dXJlLXBhcnQtMTIzNDU2Nzg5MA'].join('.');

export interface FakeOptions {
  /** the element belongs to a frame other than the main frame (an iframe), at this URL */
  iframeUrl?: string;
  onFill?: (selector: string, value: string) => void;
  /** the main frame moves to this URL while the lookup waits (redirect), so the element is found in the new document */
  redirectDuringWait?: string;
  /** the main frame moves to this URL after the owner check; the handle stays attached */
  redirectAfterOwnerCheck?: string;
  /** the element is detached after the owner check (navigation) */
  detachAfterOwnerCheck?: boolean;
  fillError?: (value: string) => Error;
  selectors?: string[];
}

export function fakePage(url: string, o: FakeOptions = {}): Fillable {
  let current = url;
  const iframe = o.iframeUrl === undefined ? null : { url: () => o.iframeUrl as string };
  const main = {
    url: () => current,
    async waitForSelector(selector: string) {
      o.selectors?.push(selector);
      if (o.redirectDuringWait) current = o.redirectDuringWait;
      let detached = false;
      return {
        async ownerFrame() {
          if (o.redirectAfterOwnerCheck) {
            const frame = iframe ?? main;
            queueMicrotask(() => void (current = o.redirectAfterOwnerCheck as string));
            if (o.detachAfterOwnerCheck) detached = true;
            return frame;
          }
          if (o.detachAfterOwnerCheck) detached = true;
          return iframe ?? main;
        },
        async fill(value: string) {
          if (detached) throw new Error('Element is not attached to the DOM');
          if (o.fillError) throw o.fillError(value);
          o.onFill?.(selector, value);
        },
      };
    },
  };
  return { url: () => current, mainFrame: () => main };
}
