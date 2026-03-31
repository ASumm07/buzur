// Buzur — AI Prompt Injection Defense Scanner
// Sumerian for "safety" and "a secret place"
// https://github.com/ASumm07/buzur

const structural = [
  /\|im_start\|[\s\S]*?\|im_end\|/gi,
  /<\|.*?\|>/gi,
  /<<SYS>>[\s\S]*?<\/SYS>/gi,
  /\[INST\][\s\S]*?\[\/INST\]/gi,
  /\[SYSTEM\]/gi,
];

const semantic = [
  /ignore (your )?(previous|prior|above|all) instructions/gi,
  /disregard (your )?(previous|prior|above|all) instructions/gi,
  /forget (your )?(previous|prior|above|all) instructions/gi,
  /new (system )?prompt:/gi,
  /override (your )?(instructions|programming|directives)/gi,
  /from now on (you will|you are|respond as)/gi,
  /you are now (a |an )?(different|new|another)/gi,
  /adopt a (new |different )?persona/gi,
  /pretend (you are|to be) (a |an )?/gi,
  /your (new |true |real |actual )?instructions are/gi,
  /respond only as/gi,
  /you must (now |always |only )?follow/gi,
];

const tier1Domains = [
  "pubmed.ncbi.nlm.nih.gov", "nih.gov", "cdc.gov", "who.int",
  "nature.com", "science.org", "nasa.gov", "noaa.gov",
  "rockwellautomation.com", "se.com", "siemens.com",
  "new.abb.com", "eaton.com", "idec.com", "phoenixcontact.com",
];

const technicalPatterns = [
  /part number|model number|datasheet|catalog|spec/i,
  /allen.?bradley|rockwell|schneider|siemens|eaton|abb|idec|phoenix contact/i,
  /pubmed|research|study|journal|clinical/i,
  /nih|cdc|fda|who\.int|nasa|noaa/i,
];


// -- Homoglyph Normalizer
// Maps lookalike Unicode characters back to their ASCII equivalents
const homoglyphs = {
  'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o',
  'р': 'r', 'с': 'c', 'х': 'x', 'у': 'y',
  'Β': 'B', 'Α': 'A', 'Ο': 'O', 'Γ': 'r',
  'Δ': 'D', 'Ε': 'E', 'Η': 'H', 'Ι': 'I',
  'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ρ': 'P',
  'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
};

export function normalizeHomoglyphs(text) {
  if (!text) return text;
  return text.split('').map(c => homoglyphs[c] || c).join('');
}


// -- Base64 Decoder
// Detects base64 encoded strings and scans decoded content for injection patterns
// Attackers encode injections to bypass pattern matching

function decodeBase64Segments(text) {
  if (!text) return text;
  const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g;
  return text.replace(base64Pattern, (match) => {
    try {
      const decoded = Buffer.from(match, 'base64').toString('utf8');
      // Only replace if decoded text is printable and different from original
      if (/^[\x20-\x7E]+$/.test(decoded) && decoded !== match) {
        return decoded;
      }
      return match;
    } catch {
      return match;
    }
  });
}

export function scan(text) {
  if (!text) return { clean: text, blocked: 0, triggered: [] };
  let s = normalizeHomoglyphs(text);
  s = decodeBase64Segments(s);
  let blocked = 0;
  const triggered = [];
  for (const p of structural) {
    const before = s;
    s = s.replace(p, "[BLOCKED]");
    if (s !== before) { blocked++; triggered.push(p.toString()); }
  }
  for (const p of semantic) {
    const before = s;
    s = s.replace(p, "[BLOCKED]");
    if (s !== before) { blocked++; triggered.push(p.toString()); }
  }
  return { clean: s, blocked, triggered };
}

export function getTrustTier(query) {
  return technicalPatterns.some(p => p.test(query)) ? "technical" : "general";
}

export function isTier1Domain(url) {
  try {
    const hostname = new URL(url).hostname.replace(/^www\./, "");
    return tier1Domains.some(d => hostname === d || hostname.endsWith("." + d));
  } catch { return false; }
}

export function addTrustedDomain(domain) {
  if (!tier1Domains.includes(domain)) tier1Domains.push(domain);
}

export default { scan, getTrustTier, isTier1Domain, addTrustedDomain, normalizeHomoglyphs, decodeBase64Segments };
