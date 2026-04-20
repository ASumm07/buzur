// Buzur — AI Prompt Injection Defense Scanner
// Sumerian for "safety" and "a secret place"
// https://github.com/ASumm07/buzur

import { decodeBase64Segments, normalizeHomoglyphs, stripHtmlObfuscation } from './characterScanner.js';
import { scanEvasion } from './evasionScanner.js';
export { decodeBase64Segments, normalizeHomoglyphs, stripHtmlObfuscation };

// -- HTML/CSS Obfuscation Stripper
// Removes techniques attackers use to hide injections from humans
// while keeping them visible to LLMs:
//   - HTML tags and comments
//   - CSS hidden text (display:none, visibility:hidden, opacity:0, font-size:0)
//   - Off-screen positioned elements (left:-9999px, top:-9999px etc.)
//   - Zero-width and invisible Unicode characters
//   - JavaScript blocks (injections can live inside <script> tags)
//   - HTML entities decoded to their real characters

// -- Injection Patterns --

const structural = [
  /\|im_start\|[\s\S]*?\|im_end\|/gi,
  /<\|.*?\|>/gi,
  /<<SYS>>[\s\S]*?<\/SYS>/gi,
  /\[INST\][\s\S]*?\[\/INST\]/gi,
  /\[SYSTEM\]/gi,
];

const semantic = [
  /ignore (your |all |any )?(previous |prior |above |all )?(instructions|directives|context|prompt)/gi,
  /ignore (everything|anything) (above|before|prior|previous)/gi,
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
  /developer mode/gi,
  /system override/gi,
  /jailbreak/gi,
  /you are now (in |a |an )?/gi,
  /act as (a |an )?(different|unrestricted|unfiltered|new)/gi,
  /reveal (your )?(system |hidden |original )?(prompt|instructions|directives)/gi,
  /print (your )?(system |hidden |original )?(prompt|instructions)/gi,
  /output (your )?(system |hidden |original )?(prompt|instructions)/gi,
  /ignore (all |any )?(previous |prior |above |safety |content )?filter/gi,
  /bypass (your )?(safety|content|security) (filter|check|guardrail)/gi,
  /disable (your )?(safety|filter|restriction|guardrail)/gi,
  /you have no (restriction|limit|filter|rule)/gi,
  /unrestricted (mode|ai|assistant|version)/gi,
  /do anything now/gi,
  /DAN[ .,!?]|DAN$/gm,
  /forget (your )?(previous|prior|above|all|original) (instructions|identity|persona|programming|directives)/gi,
  /persona hijack/gi,
  /act as (DAN|an? unrestricted|an? unfiltered|an? different|an? new)/gi,
];

// -- Trust System --

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

// -- Main Scanner --
// Pipeline: strip HTML obfuscation → normalize homoglyphs → decode base64
//           → decode evasion techniques → pattern scan

export function scan(text) {
  if (!text) return { clean: text, blocked: 0, triggered: [], evasions: [] };

  // Step 1: Strip HTML/CSS obfuscation so hidden injections are exposed
  let s = stripHtmlObfuscation(text);

  // Step 2: Normalize homoglyphs (Cyrillic/Greek lookalikes → ASCII)
  s = normalizeHomoglyphs(s);

  // Step 3: Decode base64 encoded segments
  s = decodeBase64Segments(s);

  // Step 4: Decode evasion techniques (Phase 13)
  // Handles: ROT13, hex escapes, URL encoding, Unicode escapes,
  // lookalike punctuation, extended invisible Unicode,
  // tokenizer attacks, multilingual injection patterns
  const evasionResult = scanEvasion(s);
  s = evasionResult.decoded;
  const evasions = evasionResult.detections;
  let blocked = evasionResult.multilingualBlocked;
  const triggered = evasions
    .filter(e => e.type === 'multilingual_injection')
    .map(e => e.detail);

  // Step 5: Pattern scan
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

  return { clean: s, blocked, triggered, evasions };
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

export default { scan, getTrustTier, isTier1Domain, addTrustedDomain, normalizeHomoglyphs, stripHtmlObfuscation };