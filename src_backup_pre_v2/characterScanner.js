// Buzur — Phases 1 & 2: Character-Level Defense
// Phase 1: HTML/CSS Obfuscation Stripping
// Phase 2: Homoglyph Normalization & Base64 Decoding
//
// Detects:
//   - HTML tags, comments, hidden CSS (display:none, visibility:hidden etc.)
//   - Off-screen positioned elements
//   - Zero-width and invisible Unicode characters
//   - JavaScript blocks
//   - HTML entities decoded to real characters
//   - Cyrillic/Greek lookalike characters mapped to ASCII
//   - Base64 encoded injection payloads

// -------------------------------------------------------
// PHASE 1: HTML/CSS Obfuscation Stripper
// -------------------------------------------------------

const INVISIBLE_UNICODE = /[\u00AD\u200B\u200C\u200D\u2060\uFEFF\u180E\u00A0]/g;

const HTML_ENTITIES = {
  '&lt;':   '<',  '&gt;':   '>',  '&amp;':  '&',
  '&quot;': '"',  '&#39;':  "'",  '&nbsp;': ' ',
  '&#x27;': "'",  '&#x2F;': '/',  '&#47;':  '/',
};

function decodeHtmlEntities(text) {
  return text.replace(/&[a-zA-Z0-9#]+;/g, (entity) => {
    return HTML_ENTITIES[entity] || entity;
  });
}

export function stripHtmlObfuscation(text) {
  if (!text) return text;

  // 1. Remove <script>...</script> blocks
  text = text.replace(/<script[^>]*>([\s\S]*?)<\/script>/gi, ' $1 ');

  // 2. Remove <style>...</style> blocks
  text = text.replace(/<style[\s\S]*?<\/style>/gi, ' ');

  // 3. Remove HTML comments
  text = text.replace(/<!--([\s\S]*?)-->/gim, ' $1 ');

  // 4. Strip inline CSS hiding patterns
  text = text.replace(
    /style\s*=\s*["'][^"']*?(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)[^"']*?["']/gi,
    'style="[HIDDEN]"'
  );
  text = text.replace(
    /style\s*=\s*["'][^"']*?(left|top|right|bottom)\s*:\s*-\d{3,}[^"']*?["']/gi,
    'style="[OFFSCREEN]"'
  );

  // 5. Remove all remaining HTML tags
  text = text.replace(/<[^>]+>/g, ' ');

  // 6. Decode HTML entities
  text = decodeHtmlEntities(text);

  // 7. Remove invisible Unicode characters
  text = text.replace(INVISIBLE_UNICODE, '');

  // 8. Collapse excess whitespace
  text = text.replace(/\s{3,}/g, '  ').trim();

  return text;
}

// -------------------------------------------------------
// PHASE 2: Homoglyph Normalization & Base64 Decoding
// -------------------------------------------------------

const HOMOGLYPHS = {
  'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o',
  'р': 'r', 'с': 'c', 'х': 'x', 'у': 'y',
  'Β': 'B', 'Α': 'A', 'Ο': 'O', 'Γ': 'r',
  'Δ': 'D', 'Ε': 'E', 'Η': 'H', 'Ι': 'I',
  'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ρ': 'P',
  'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
};

export function normalizeHomoglyphs(text) {
  if (!text) return text;
  return text.split('').map(c => HOMOGLYPHS[c] || c).join('');
}

export function decodeBase64Segments(text) {
  if (!text) return text;
  const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g;
  return text.replace(base64Pattern, (match) => {
    try {
      const decoded = Buffer.from(match, 'base64').toString('utf8');
      if (/^[\x20-\x7E]+$/.test(decoded) && decoded !== match) {
        return decoded;
      }
      return match;
    } catch {
      return match;
    }
  });
}

export default { stripHtmlObfuscation, normalizeHomoglyphs, decodeBase64Segments };