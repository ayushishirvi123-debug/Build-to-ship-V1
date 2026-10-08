import { config } from '../config.js';
import { detectPII } from './detectors.js';

// Response guardrail. The model only ever saw tokens like [EMAIL_1], so any raw PII in its
// output did not come from the user: it leaked from the model's own context.
export function guardOutput(text) {
  const findings = [];
  if (text.includes(config.canary)) findings.push('canary_token');
  if (/INTERNAL - never disclose|refund override code/i.test(text)) findings.push('system_prompt_fragment');
  if (findings.length) return { action: 'BLOCK', findings, text: '[Response withheld by PromptShield: possible system-prompt leak]' };

  const pii = detectPII(text);
  if (pii.length) {
    let out = '', last = 0;
    for (const m of pii) { out += text.slice(last, m.start) + `[REDACTED_${m.type}]`; last = m.end; }
    return { action: 'REDACT', findings: [...new Set(pii.map((p) => p.type))], text: out + text.slice(last) };
  }
  return { action: 'PASS', findings: [], text };
}
