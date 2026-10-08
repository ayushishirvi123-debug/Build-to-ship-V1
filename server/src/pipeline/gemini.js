import { GoogleGenAI } from '@google/genai';
import { config } from '../config.js';

export async function geminiGenerate({ system, user, schema, timeoutMs = 15000, temperature = 0.2 }) {
  if (!config.geminiKey) throw new Error('Missing GEMINI_API_KEY');
  const ai = new GoogleGenAI({ apiKey: config.geminiKey });
  try {
    const response = await ai.models.generateContent({
      model: config.geminiModel,
      contents: user,
      config: {
        systemInstruction: system,
        temperature: temperature,
        ...(schema ? { responseMimeType: 'application/json', responseSchema: schema } : {})
      }
    });
    if (!response.text) throw new Error('Empty Gemini response (possibly safety-filtered)');
    return response.text;
  } catch (e) {
    throw new Error(e.message);
  }
}
