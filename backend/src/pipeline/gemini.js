import { config } from '../config.js';

// Minimal Gemini REST client. The API key only ever lives in backend env vars.
export async function geminiGenerate({ system, user, schema, timeoutMs = 15000, temperature = 0.2 }) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${config.geminiModel}:generateContent`;
  const body = {
    systemInstruction: { parts: [{ text: system }] },
    contents: [{ role: 'user', parts: [{ text: user }] }],
    generationConfig: { temperature, ...(schema ? { responseMimeType: 'application/json', responseSchema: schema } : {}) },
  };
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-goog-api-key': config.geminiKey },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    if (!r.ok) throw new Error(`Gemini HTTP ${r.status}`);
    const j = await r.json();
    const text = j.candidates?.[0]?.content?.parts?.map((p) => p.text || '').join('') || '';
    if (!text) throw new Error('Empty Gemini response (possibly safety-filtered)');
    return text;
  } catch (e) {
    throw new Error(e.name === 'AbortError' ? `Gemini timeout after ${timeoutMs}ms` : e.message);
  } finally {
    clearTimeout(timer);
  }
}
