// Buzur — Phase 13: Evasion Technique Defense
// Detects and neutralizes encoding and character manipulation attacks
// https://github.com/SummSolutions/buzur

import { defaultLogger, logThreat } from './buzurLogger.js';

// Full set — Phase 1 INVISIBLE_UNICODE is now aligned with this
export const EXTENDED_INVISIBLE = /[\u00AD\u200B\u200C\u200D\u2060\uFEFF\u180E\u00A0\u115F\u1160\u3164\uFFA0\u034F\u2028\u2029\u202A\u202B\u202C\u202D\u202E\u206A\u206B\u206C\u206D\u206E\u206F]/g;

const PUNCTUATION_MAP = {
  '\u2018': "'", '\u2019': "'", '\u201A': "'", '\u201B': "'",
  '\u201C': '"', '\u201D': '"', '\u201E': '"', '\u201F': '"',
  '\u2014': '-', '\u2013': '-', '\u2012': '-', '\u2010': '-', '\u2011': '-',
  '\u2026': '...', '\u00AB': '"', '\u00BB': '"', '\u2039': "'", '\u203A': "'",
  '\u02BC': "'", '\u02BB': "'",
};

export function normalizePunctuation(text) {
  if (!text) return text;
  return text.split('').map(c => PUNCTUATION_MAP[c] || c).join('');
}

const EVASION_KEYWORDS = [
  'ignore', 'override', 'forget', 'disregard', 'bypass',
  'jailbreak', 'unrestricted', 'instructions', 'directives',
  'system', 'prompt', 'persona', 'pretend', 'developer',
  'disable', 'filter', 'restriction', 'injection',
  'vtagber', 'bireevqr', 'sbetrg', 'qvfertneq', 'olmhyhfr',
];

export function decodeRot13(text) {
  if (!text) return text;
  return text.replace(/[a-zA-Z]{4,}/g, (word) => {
    const decoded = word.replace(/[a-zA-Z]/g, c => {
      const base = c <= 'Z' ? 65 : 97;
      return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
    });
    return EVASION_KEYWORDS.some(k => decoded.toLowerCase().includes(k)) ? decoded : word;
  });
}

export function decodeHexEscapes(text) {
  if (!text) return text;
  return text.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

export function decodeUrlEncoding(text) {
  if (!text) return text;
  try {
    return text.replace(/(%[0-9a-fA-F]{2}){3,}/g, (match) => { try { return decodeURIComponent(match); } catch { return match; } });
  } catch { return text; }
}

export function decodeUnicodeEscapes(text) {
  if (!text) return text;
  return text.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

export function reconstructTokenizerAttacks(text) {
  if (!text) return text;
  let r = text.replace(EXTENDED_INVISIBLE, '');
  r = r.replace(/\b([a-zA-Z] ){3,}[a-zA-Z]\b/g, m => m.replace(/ /g, ''));
  r = r.replace(/\b([a-zA-Z]\.){3,}[a-zA-Z]\b/g, m => m.replace(/\./g, ''));
  r = r.replace(/\b([a-zA-Z]{2,6})-([a-zA-Z]{2,6})\b/g, (match, a, b) => {
    const joined = a + b;
    return EVASION_KEYWORDS.some(k => joined.toLowerCase().includes(k)) ? joined : match;
  });
  return r;
}

const MULTILINGUAL_PATTERNS = [
  /ignorez (vos |toutes |les )?(instructions|directives|consignes) (précédentes|antérieures)/gi,
  /oubliez (vos )?(instructions|directives) (précédentes|antérieures)/gi,
  /désactivez (vos )?(filtres?|restrictions?)/gi,
  /nouvelles? instructions?:/gi,
  /à partir de maintenant (vous|tu) (êtes|es|devez|dois)/gi,
  /contournez? (vos )?(filtres?|sécurité|restrictions?)/gi,
  /ignora (tus |todas |las )?(instrucciones|directivas) (anteriores|previas)/gi,
  /olvida (tus )?(instrucciones|directivas) (anteriores|previas)/gi,
  /desactiva (tus )?(filtros?|restricciones?)/gi,
  /nuevas? instrucciones?:/gi,
  /a partir de ahora (eres|debes|responde)/gi,
  /omite (tus )?(instrucciones|restricciones) (anteriores|previas)/gi,
  /ignoriere (deine |alle |die )?(vorherigen |früheren )?(Anweisungen|Direktiven)/gi,
  /vergiss (deine )?(vorherigen |früheren )?(Anweisungen|Direktiven)/gi,
  /deaktiviere (deine )?(Filter|Einschränkungen)/gi,
  /neue Anweisungen:/gi,
  /ab jetzt (bist du|musst du|antworte)/gi,
  /umgehe (deine )?(Filter|Sicherheit|Einschränkungen)/gi,
  /ignora (le tue |tutte le |le )?(istruzioni|direttive) (precedenti|anteriori)/gi,
  /dimentica (le tue )?(istruzioni|direttive) (precedenti|anteriori)/gi,
  /disattiva (i tuoi )?(filtri|restrizioni)/gi,
  /nuove istruzioni:/gi,
  /da ora in poi (sei|devi|rispondi)/gi,
  /ignore (suas |todas as |as )?(instruções|diretivas) (anteriores|prévias)/gi,
  /esqueça (suas )?(instruções|diretivas) (anteriores|prévias)/gi,
  /desative (seus )?(filtros?|restrições)/gi,
  /novas instruções:/gi,
  /a partir de agora (você é|você deve|responda)/gi,
  /игнорируй (предыдущие |все )?(инструкции|директивы)/gi,
  /забудь (предыдущие )?(инструкции|директивы)/gi,
  /отключи (фильтры|ограничения)/gi,
  /новые инструкции:/gi,
  /отныне (ты|вы) (являешься|должен|должны)/gi,
  /忽略(之前的|所有的|你的)?(指令|命令|提示)/g,
  /忘记(之前的|所有的)?(指令|命令)/g,
  /新的指令:/g,
  /从现在起(你是|你必须|你应该)/g,
  /绕过(你的)?(过滤|限制|安全)/g,
  /تجاهل (التعليمات|الأوامر) (السابقة)/g,
  /انسَ (التعليمات|الأوامر) السابقة/g,
  /تعليمات جديدة:/g,
  /من الآن فصاعداً (أنت|يجب عليك)/g,
];

export function scanEvasion(text, options = {}) {
  if (!text) return { decoded: text, detections: [], multilingualBlocked: 0 };

  const logger = options.logger || defaultLogger;
  const detections = [];
  let s = text;

  const beforeInvisible = s;
  s = s.replace(EXTENDED_INVISIBLE, '');
  if (s !== beforeInvisible) detections.push({ type: 'invisible_unicode', severity: 'medium', detail: 'Extended invisible Unicode characters removed' });

  const beforePunct = s;
  s = normalizePunctuation(s);
  if (s !== beforePunct) detections.push({ type: 'punctuation_normalization', severity: 'low', detail: 'Lookalike punctuation normalized' });

  const beforeHex = s;
  s = decodeHexEscapes(s);
  if (s !== beforeHex) detections.push({ type: 'hex_encoding', severity: 'high', detail: 'Hex-encoded characters decoded' });

  const beforeUrl = s;
  s = decodeUrlEncoding(s);
  if (s !== beforeUrl) detections.push({ type: 'url_encoding', severity: 'high', detail: 'URL-encoded characters decoded' });

  const beforeUnicode = s;
  s = decodeUnicodeEscapes(s);
  if (s !== beforeUnicode) detections.push({ type: 'unicode_escapes', severity: 'high', detail: 'Unicode escape sequences decoded' });

  const beforeRot13 = s;
  s = decodeRot13(s);
  if (s !== beforeRot13) detections.push({ type: 'rot13_encoding', severity: 'high', detail: 'ROT13-encoded injection keywords decoded' });

  const beforeTokenizer = s;
  s = reconstructTokenizerAttacks(s);
  if (s !== beforeTokenizer) detections.push({ type: 'tokenizer_attack', severity: 'high', detail: 'Tokenizer evasion reconstructed' });

  let multilingualBlocked = 0;
  for (const pattern of MULTILINGUAL_PATTERNS) {
    const before = s;
    s = s.replace(pattern, '[BLOCKED]');
    if (s !== before) {
      multilingualBlocked++;
      detections.push({ type: 'multilingual_injection', severity: 'high', detail: `Multilingual injection pattern detected` });
    }
    pattern.lastIndex = 0;
  }

  const result = { decoded: s, detections, multilingualBlocked };

  // Log if any evasion technique was detected
  if (detections.length > 0) {
    logThreat(13, 'evasionScanner', result, text.slice(0, 200), logger);
    // onThreat only on high-severity — low/medium (invisible chars, punctuation) fall through
    const hasHighSeverity = detections.some(d => d.severity === 'high');
    if (hasHighSeverity) {
      const onThreat = options.onThreat || 'skip';
      if (onThreat === 'skip') return { skipped: true, blocked: detections.filter(d => d.severity === 'high').length, reason: `Buzur blocked evasion: ${detections.find(d => d.severity === 'high')?.type}`, decoded: s, detections, multilingualBlocked };
      if (onThreat === 'throw') throw new Error(`Buzur blocked evasion technique: ${detections.find(d => d.severity === 'high')?.type}`);
    }
  }

  return result;
}

export default { scanEvasion, normalizePunctuation, decodeRot13, decodeHexEscapes, decodeUrlEncoding, decodeUnicodeEscapes, reconstructTokenizerAttacks };