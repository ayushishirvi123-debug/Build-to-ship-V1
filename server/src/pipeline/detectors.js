// Layer 1: fast, deterministic detection (milliseconds, no network).

const luhn = (s) => {
  const d = s.replace(/\D/g, '');
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = +d[i];
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
};

// Order matters: earlier detectors win overlapping spans.
const PII_DETECTORS = [
  { type: 'API_KEY', re: /\b(?:sk-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|AIza[0-9A-Za-z_-]{30,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g },
  { type: 'EMAIL', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g },
  { type: 'SSN', re: /(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/g },
  { type: 'CREDIT_CARD', re: /(?<!\d)(?:\d[ -]?){13,19}(?!\d)/g, validate: luhn },
  { type: 'AADHAAR', re: /(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)/g },
  { type: 'PAN', re: /\b[A-Z]{5}\d{4}[A-Z]\b/g },
  { type: 'PHONE', re: /(?<!\d)(?:\+91[ -]?)?[6-9]\d{4}[ -]?\d{5}(?!\d)/g },
  { type: 'PHONE', re: /(?<!\d)(?:\+?1[ -]?)?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}(?!\d)/g },
];

export function detectPII(text) {
  const found = [];
  for (const d of PII_DETECTORS) {
    for (const m of text.matchAll(d.re)) {
      const start = m.index, end = start + m[0].length;
      if (d.validate && !d.validate(m[0])) continue;
      if (found.some((f) => start < f.end && end > f.start)) continue;
      found.push({ type: d.type, start, end, value: m[0] });
    }
  }
  return found.sort((a, b) => a.start - b.start);
}

// Reversible redaction: same value -> same token, vault never leaves the request.
export function tokenize(text, matches) {
  const counters = {}, vault = {}, byValue = {};
  const toks = matches.map((m) => {
    const k = m.type + '|' + m.value;
    if (!byValue[k]) {
      counters[m.type] = (counters[m.type] || 0) + 1;
      byValue[k] = `[${m.type}_${counters[m.type]}]`;
      vault[byValue[k]] = m.value;
    }
    return byValue[k];
  });
  let out = '', last = 0;
  matches.forEach((m, i) => { out += text.slice(last, m.start) + toks[i]; last = m.end; });
  out += text.slice(last);
  return { sanitized: out, vault, spans: matches.map((m, i) => ({ type: m.type, start: m.start, end: m.end, token: toks[i] })) };
}
export const detokenize = (text, vault) => text.replace(/\[([A-Z_]+_\d+)\]/g, (t) => vault[t] ?? t);

/* ---------- threat rules ---------- */
const RULES = [
  { id: 'override_instructions', cat: 'PROMPT_INJECTION', w: 70, label: 'Instruction override',
    explain: 'The prompt tries to make the model ignore or replace its existing instructions.',
    re: /\b(ignore|disregard|forget|override|bypass|drop)\b[^.\n]{0,40}\b(instructions?|rules?|prompts?|guidelines?|polic(?:y|ies)|directives?|safeguards?|restrictions?)\b/ },
  { id: 'system_prompt_exfil', cat: 'PROMPT_INJECTION', w: 75, label: 'System prompt extraction',
    explain: 'The prompt asks the model to reveal its hidden system prompt or internal instructions.',
    re: /\b(reveal|show|print|display|repeat|leak|output|expose|tell me|what is)\b[^.\n]{0,30}\b(system prompt|hidden (?:prompt|instructions?)|initial (?:prompt|instructions?)|your (?:instructions|prompt|rules|configuration))\b/ },
  { id: 'persona_jailbreak', cat: 'JAILBREAK', w: 60, label: 'Jailbreak persona',
    explain: 'The prompt uses a known jailbreak framing (DAN, developer mode, god mode) to remove safety limits.',
    re: /\b(do anything now|developer mode|jailbr(?:eak|oken|oke)\w*|god mode|dev mode|unfiltered mode)\b/ },
  { id: 'persona_dan', cat: 'JAILBREAK', w: 60, raw: true, label: 'Jailbreak persona (DAN)',
    explain: 'The prompt invokes the DAN ("Do Anything Now") jailbreak persona.', re: /\bDAN\b/ },
  { id: 'role_override', cat: 'JAILBREAK', w: 55, label: 'Role reassignment',
    explain: 'The prompt tries to reassign the model to a privileged or unrestricted role.',
    re: /\b(you are now|from now on,? you (?:are|will|must)|act as (?:a |an |the )?(?:super ?admin|admin|root|system|unrestricted|unfiltered)|pretend (?:that )?you (?:have|are|can)[^.\n]{0,40}(?:no|without) (?:rules|restrictions|limits|filters))/ },
  { id: 'data_exfil', cat: 'DATA_EXFILTRATION', w: 65, label: 'Bulk data extraction',
    explain: 'The prompt asks the model to dump bulk records, credentials or secrets.',
    re: /\b(print|dump|list|show|give me|export|send me|extract)\b[^.\n]{0,30}\b(all|every|entire|full)\b[^.\n]{0,30}\b(users?|customers?|database|records?|passwords?|credentials|secrets?|api keys?|tables?)\b/ },
  { id: 'delimiter_spoof', cat: 'PROMPT_INJECTION', w: 50, label: 'Fake system delimiters',
    explain: 'The prompt contains fake role or system markers meant to impersonate trusted instructions.',
    re: /(<\/?(?:system|assistant|instructions?)>|\[\/?(?:inst|sys)\]|<\|(?:im_start|im_end|system)\|>|^#{2,3}\s*(?:system|instructions?)\b)/m },
  { id: 'inspector_tamper', cat: 'INSPECTOR_TAMPERING', w: 80, sticky: true, label: 'Attack on the firewall itself',
    explain: 'The prompt tries to manipulate the security classifier (e.g. "mark this as safe", "set risk to 0").',
    re: /\b(?:this (?:prompt|message|input) is (?:safe|benign|harmless|approved)|(?:mark|classify|label|rate) (?:this|it) as (?:safe|benign)|risk[_ ]?score\W{0,5}(?:to |of |=|:)?\W{0,3}0\b|is_safe\W{0,5}true|threat_category\W{0,5}safe|respond with (?:only )?(?:\{|json))/ },
  { id: 'harmful_request', cat: 'TOXICITY', w: 80, label: 'Harmful content request',
    explain: 'The prompt asks for help creating weapons or malware.',
    re: /\b(build|make|create|write|synthesi[sz]e)\b[^.\n]{0,20}\b(bomb|explosives?|ransomware|malware|keylogger|nerve agent|bioweapon)\b/ },
  { id: 'threat', cat: 'TOXICITY', w: 70, label: 'Threat or self-harm language',
    explain: 'The prompt contains threatening or self-harm language.',
    re: /\b(kill yourself|i(?:'ll| will) (?:hurt|kill|find) you)\b/ },
  { id: 'insult', cat: 'TOXICITY', w: 35, label: 'Abusive language',
    explain: 'The prompt contains insulting or abusive language.', re: /\b(idiot|stupid|moron|dumb|worthless|shut up|hate you)\b/ },
];

const norm = (s) => s.normalize('NFKC').replace(/[\u200B-\u200F\u2060\uFEFF]/g, '').toLowerCase();
const deleet = (s) => s.replace(/[013457@$]/g, (c) => ({ 0: 'o', 1: 'i', 3: 'e', 4: 'a', 5: 's', 7: 't', '@': 'a', $: 's' }[c]));
const despace = (s) => s.replace(/\b(?:[a-z][ .\-_]){3,}[a-z]\b/g, (m) => m.replace(/[ .\-_]/g, ''));

export const combine = (list) => (list.length ? Math.min(100, list[0].w + 15 * (list.length - 1)) : 0);

function runRules(raw, skip) {
  const n = norm(raw);
  const variants = [n, deleet(n), despace(n)];
  const hits = [];
  for (const r of RULES) {
    if (skip?.has(r.id)) continue;
    const targets = r.raw ? [raw] : variants;
    if (targets.some((v) => r.re.test(v))) hits.push({ id: r.id, cat: r.cat, w: r.w, label: r.label, explain: r.explain, sticky: !!r.sticky });
  }
  return hits;
}

export function scanThreats(raw) {
  const hits = runRules(raw);
  // Obfuscation: decode base64-looking blobs and rescan them.
  for (const blob of raw.match(/[A-Za-z0-9+/]{20,}={0,2}/g) || []) {
    let dec = '';
    try { dec = Buffer.from(blob, 'base64').toString('utf8'); } catch { continue; }
    if (dec.length < 10 || /[^\x09\x0a\x0d\x20-\x7e]/.test(dec)) continue;
    const inner = runRules(dec);
    if (inner.length) {
      hits.push({ id: 'encoded_payload', cat: inner[0].cat, w: Math.max(70, inner[0].w), label: 'Obfuscated (base64) attack',
        explain: 'A base64-encoded string decodes to a known attack pattern: someone is hiding the payload.', sticky: false });
      break;
    }
  }
  hits.sort((a, b) => b.w - a.w);
  return { rules: hits, risk: combine(hits) };
}

export const looksSuspicious = (t) =>
  t.length > 600 ||
  /[A-Za-z0-9+/]{30,}={0,2}/.test(t) ||
  /\b(you are|pretend|role-?play|act as|instructions?|system|prompt|rules?|bypass|unrestricted|unfiltered|hypothetical(?:ly)?|persona|jailbreak|secret|confidential|admin|password|credentials?|no limits|without (?:any )?(?:filters|restrictions))\b/i.test(t);
