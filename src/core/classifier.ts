import { detect } from './detect.ts';
import type { Span } from './detect.ts';

export interface Classifier {
  readonly name: string;
  classify(text: string): Promise<Span[]>;
}

export const RULES_ONLY = 'rules-only';

export class NotConfigured extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotConfigured';
  }
}

/** `--local` mode: the deterministic detectors only, nothing leaves the process. */
export class RulesOnly implements Classifier {
  readonly name = RULES_ONLY;
  async classify(text: string): Promise<Span[]> {
    return detect(text);
  }
}

/** Placeholder for the TEE classifier. Phase 1 makes no network calls. */
export class NearAiCloud implements Classifier {
  readonly name = 'near-ai-cloud';
  #env: NodeJS.ProcessEnv;
  constructor(env: NodeJS.ProcessEnv = process.env) {
    this.#env = env;
  }
  async classify(_text: string): Promise<Span[]> {
    if (!this.#env.NEAR_AI_CLOUD_API_KEY) throw new NotConfigured('NEAR_AI_CLOUD_API_KEY is not set');
    throw new NotConfigured('the NEAR AI Cloud classifier is not implemented in this version');
  }
}
