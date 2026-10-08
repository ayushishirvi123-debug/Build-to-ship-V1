import { detectPII, tokenize, detokenize, scanThreats, looksSuspicious, combine } from './detectors.js';
import { inspect } from './inspector.js';
import { callLLM } from './llm.js';
import { guardOutput } from './outputGuard.js';
import { config } from '../config.js';

export const THRESH = { low: 80, medium: 60, high: 40 };
const ms = (t) => +(performance.now() - t).toFixed(1);

export async function runPipeline({ prompt, policy, guardrails = true, runDownstream = true }) {
  const T0 = performance.now();
  const stages = [];
  const add = (name, layer, t, status, detail) => stages.push({ name, layer, ms: ms(t), status, detail });

  const piiMatches = detectPII(prompt);
  const tok = tokenize(prompt, piiMatches); // always computed: used for storage + inspector input

  /* ---- guardrails OFF: the "raw app" baseline ---- */
  if (!guardrails) {
    let t = performance.now();
    const llm = await callLLM({ prompt });
    add('Downstream LLM (no protection)', 'llm', t, 'warn', llm.mode);
    const leak = guardOutput(llm.text);
    return {
      action: 'UNGUARDED', category: 'NONE', risk: 0, source: 'none',
      reason: 'Guardrails were off, so the prompt went straight to the model.',
      rules: [], spans: [], storedPrompt: tok.sanitized, llmInput: prompt, response: llm.text,
      llmMode: llm.mode, leaked: leak.action !== 'PASS', stages,
      latency: { guard: 0, llm: stages[0].ms, total: ms(T0) }, totalMs: ms(T0),
    };
  }

  /* ---- layer 1: regex + PII ---- */
  let t = performance.now();
  const threats = scanThreats(prompt);
  const rules = threats.rules.filter((r) => (r.cat === 'TOXICITY' ? policy.toxicityDetection : policy.injectionDetection));
  const regexRisk = combine(rules);
  const threshold = THRESH[policy.strictness] ?? 60;
  add('Regex scan', 'regex', t, regexRisk >= threshold ? 'flag' : 'pass', `${rules.length} rule hit(s)`);

  t = performance.now();
  const masking = policy.piiMasking && piiMatches.length > 0;
  add('PII tokenizer', 'regex', t, piiMatches.length ? 'redact' : 'pass',
    piiMatches.length ? `${piiMatches.length} item(s) → tokens${policy.piiMasking ? '' : ' (masking off: flagged only)'}` : 'no PII found');

  /* ---- layer 2: tiered Gemini inspection ---- */
  const sticky = rules.some((r) => r.sticky) || regexRisk >= 70;
  const aiAvailable = !!config.geminiKey && policy.aiMode !== 'off';
  const needAI = aiAvailable && !sticky && (policy.aiMode === 'always' || regexRisk > 0 || looksSuspicious(prompt));
  let ai = null;
  if (needAI) {
    t = performance.now();
    ai = await inspect(tok.sanitized);
    add('Gemini inspector', 'ai', t, ai.ok ? (ai.risk >= threshold ? 'flag' : 'pass') : 'error', ai.ok ? `${ai.category} (${ai.risk})` : ai.error);
  } else {
    add('Gemini inspector', 'ai', performance.now(), 'skipped',
      !config.geminiKey ? 'no GEMINI_API_KEY: regex-only mode' : policy.aiMode === 'off' ? 'disabled by policy'
        : sticky ? 'high-confidence regex block: AI not needed' : 'prompt looks ordinary: fast path');
  }

  /* ---- policy decision ---- */
  t = performance.now();
  let risk = regexRisk, category = rules[0]?.cat || 'SAFE', source = 'regex';
  let reason = rules.length ? rules.slice(0, 2).map((r) => r.explain).join(' ') : 'No threats detected.';
  let failClosed = false;
  if (ai?.ok) {
    source = regexRisk ? 'regex+ai' : 'ai';
    if (!sticky) {
      risk = regexRisk ? Math.round(0.3 * regexRisk + 0.7 * ai.risk) : ai.risk;
      if (ai.category !== 'SAFE' && ai.risk >= regexRisk) { category = ai.category; reason = ai.reason; }
      else if (ai.category === 'SAFE' && regexRisk) reason = 'Weak regex signals, but the AI inspector judged the prompt safe.';
    }
  } else if (ai && !ai.ok) {
    source = 'regex (AI failed)';
    if (policy.failMode === 'closed') {
      failClosed = true; category = 'INSPECTOR_ERROR'; risk = Math.max(risk, 90);
      reason = `The AI inspector was unavailable (${ai.error}); policy is fail-closed, so the request was blocked.`;
    }
  }
  const blocked = failClosed || risk >= threshold;
  let action = blocked ? 'BLOCKED' : masking ? 'REDACTED' : 'ALLOWED';
  if (!blocked) {
    category = masking ? 'PII_LEAKAGE' : 'SAFE';
    reason = masking
      ? `Masked ${piiMatches.length} sensitive item(s) (${[...new Set(piiMatches.map((m) => m.type))].join(', ')}) before they reached the model.`
      : 'No threats detected.';
    if (masking) risk = Math.max(risk, Math.min(20 + piiMatches.length * 10, 50));
  }
  add('Policy decision', 'regex', t, blocked ? 'flag' : 'pass', `${action.toLowerCase()} · risk ${risk} · threshold ${threshold}`);

  const result = {
    action, category, risk, source, reason, rules,
    spans: tok.spans, storedPrompt: tok.sanitized,
    llmInput: null, response: null, llmMode: null, leaked: false, stages,
  };

  if (blocked) {
    result.response = `Request blocked by PromptShield (${category.replace(/_/g, ' ').toLowerCase()}). ${reason}`;
  } else if (runDownstream) {
    const llmInput = policy.piiMasking ? tok.sanitized : prompt;
    result.llmInput = llmInput;
    t = performance.now();
    const llm = await callLLM({ prompt: llmInput });
    result.llmMode = llm.mode;
    add('Downstream LLM', 'llm', t, llm.mode === 'error' ? 'error' : 'pass', llm.mode);

    t = performance.now();
    const og = policy.outputGuard ? guardOutput(llm.text) : { action: 'PASS', findings: [], text: llm.text };
    add('Output guard', 'regex', t, og.action === 'PASS' ? 'pass' : 'flag', og.action === 'PASS' ? 'clean' : `${og.action.toLowerCase()}: ${og.findings.join(', ')}`);
    if (og.action === 'BLOCK') {
      Object.assign(result, { action: 'BLOCKED', category: 'OUTPUT_LEAK', risk: 95, reason: 'The model\'s response contained protected system data (canary token or internal notes), so it was withheld.' });
      result.response = og.text;
    } else {
      if (og.action === 'REDACT') result.reason += ` Output guard also redacted ${og.findings.join(', ')} from the model's response.`;
      if (masking && policy.reversibleRedaction) {
        t = performance.now();
        result.response = detokenize(og.text, tok.vault);
        add('Restore PII for user', 'regex', t, 'pass', 'tokens → original values (user only)');
      } else result.response = og.text;
    }
  }

  const sum = (layer) => +stages.filter((s) => s.layer === layer).reduce((a, s) => a + s.ms, 0).toFixed(1);
  result.latency = { regex: sum('regex'), ai: sum('ai'), llm: sum('llm'), guard: +(sum('regex') + sum('ai')).toFixed(1), total: ms(T0) };
  result.totalMs = result.latency.total;
  return result;
}
