// Buzur — Phase 14: Fuzzy Match & Prompt Leak Defense
// Catches injection attempts that evade exact pattern matching
// through deliberate misspellings, character substitutions,
// and prompt extraction/leaking attacks.
//
// Covers:
//   - Fuzzy/typo injection: misspellings, letter substitutions,
//     repeated/missing letters designed to slip past regex
//   - Leet speak substitutions: 1gnore, 0verride, 3xecute
//   - Prompt leaking: attempts to extract system prompt,
//     original instructions, or context window contents

// -------------------------------------------------------
// Leet Speak / Character Substitution Normalizer
// Maps common number/symbol substitutions back to letters
// so fuzzy matching works on normalized text
// -------------------------------------------------------
const LEET_MAP = {
  '0': 'o',
  '1': 'i',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '7': 't',
  '8': 'b',
  '@': 'a',
  '$': 's',
  '!': 'i',
  '+': 't',
};

export function normalizeLeet(text) {
  if (!text) return text;
  return text.split('').map(c => LEET_MAP[c] || c).join('');
}

// -------------------------------------------------------
// Levenshtein Distance
// Measures how many single-character edits (insertions,
// deletions, substitutions) are needed to transform
// one string into another.
// Used to catch near-miss injection keywords.
// -------------------------------------------------------
export function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

// -------------------------------------------------------
// Injection keywords to fuzzy-match against
// These are the core words attackers try to obfuscate
// -------------------------------------------------------
const FUZZY_KEYWORDS = [
  'ignore',
  'override',
  'disregard',
  'jailbreak',
  'bypass',
  'instructions',
  'directives',
  'unrestricted',
  'forbidden',
  'restricted',
];

// Maximum edit distance to consider a match
// Distance of 2 catches most typo attacks without false positives
const MAX_DISTANCE = 2;

// Minimum word length to fuzzy match — short words have too many
// accidental near-matches at distance 2
const MIN_WORD_LENGTH = 5;

// -------------------------------------------------------
// fuzzyMatchInjection(text)
// Splits text into words, normalizes leet speak,
// then checks each word against injection keywords
// using Levenshtein distance.
//
// Returns array of matches: { word, keyword, distance }
// -------------------------------------------------------
export function fuzzyMatchInjection(text) {
  if (!text) return [];

  const normalized = normalizeLeet(text.toLowerCase());
  const words = normalized.match(/[a-z]{5,}/g) || [];
  const matches = [];

  for (const word of words) {
    if (word.length < MIN_WORD_LENGTH) continue;

    for (const keyword of FUZZY_KEYWORDS) {
      // Skip if lengths are too different to possibly match
      if (Math.abs(word.length - keyword.length) > MAX_DISTANCE) continue;

      const distance = levenshtein(word, keyword);
      if (distance > 0 && distance <= MAX_DISTANCE) {
        // Avoid flagging words that are clearly unrelated
        // by requiring at least 50% character overlap
        const overlap = keyword.length - distance;
        if (overlap / keyword.length >= 0.6) {
          matches.push({ word, keyword, distance });
        }
      }
    }
  }

  return matches;
}

// -------------------------------------------------------
// Prompt Leaking Patterns
// Attempts to extract system prompt, original instructions,
// context window, or internal configuration
// -------------------------------------------------------
const PROMPT_LEAK_PATTERNS = [
  // Direct extraction requests
  /repeat (everything|all|the text|the content|what is) (above|before|prior|previously)/gi,
  /output (everything|all content|the text|what is) (above|before|prior)/gi,
  /print (everything|all|the text|what is) (above|before|prior)/gi,
  /show me (everything|all|the text|what is) (above|before|prior)/gi,
  /what (were|are) your (original |initial |system |hidden |real |true )?instructions/gi,
  /what (is|was) (in |inside )?(your )?(system |original |initial |hidden )?prompt/gi,
  /show me your (system |original |initial |hidden |real |true )?prompt/gi,
  /reveal your (system |original |initial |hidden |real |true )?prompt/gi,
  /display your (system |original |initial |hidden |real |true )?prompt/gi,
  /output your (system |original |initial |hidden |real |true )?prompt/gi,
  /print your (system |original |initial |hidden |real |true )?prompt/gi,
  /what (are|were) (the |your )?(instructions|directives|rules) (you (were|are) given|at the start|initially)/gi,
  /tell me (what |about )?(your )?(system |original |initial |hidden )?(prompt|instructions|directives)/gi,

  // Context window extraction
  /output (your |the )?(entire |full |whole |complete )?context( window)?/gi,
  /show (your |the )?(entire |full |whole |complete )?context( window)?/gi,
  /print (your |the )?(entire |full |whole |complete )?context( window)?/gi,
  /repeat (your |the )?(entire |full |whole |complete )?context( window)?/gi,
  /what (is|was|are) (in |inside )?(your |the )?(entire |full )?context( window)?/gi,

  // Partial/first line extraction
  /just (show|tell|give|print|output|repeat) me the first (line|word|sentence|part) of (your )?(instructions|prompt|context|system)/gi,
  /what('s| is) the first (line|word|sentence|part) of (your )?(instructions|prompt|system)/gi,
  /start(ing)? with the first (line|word) of (your )?(instructions|prompt|system)/gi,

  // Indirect extraction
  /summarize (your )?(system |original |initial |hidden )?(prompt|instructions|directives)/gi,
  /paraphrase (your )?(system |original |initial |hidden )?(prompt|instructions|directives)/gi,
  /translate (your )?(system |original |initial |hidden )?(prompt|instructions|directives)/gi,
  /what (constraints|rules|limits|guidelines) (were you |have you been |are you )(given|told|instructed)/gi,
  /how (were you|have you been) (instructed|programmed|configured|set up|trained)/gi,
  /what (were you|have you been) (told|instructed|programmed|configured) to (do|say|avoid|not)/gi,

  // Token/formatting tricks to extract prompt
  /```[\s\S]{0,20}(system|prompt|instructions|context)[\s\S]{0,20}```/gi,
  /\[(system|prompt|instructions|context)\]/gi,
];

// -------------------------------------------------------
// scanPromptLeak(text)
// Scans for prompt extraction and leaking attempts
//
// Returns:
//   {
//     verdict: 'clean' | 'suspicious' | 'blocked',
//     detections: [ { type, detail, severity } ],
//     clean: string  // text with leak attempts neutralized
//   }
// -------------------------------------------------------
export function scanPromptLeak(text) {
  if (!text) return { verdict: 'clean', detections: [], clean: text };

  const detections = [];
  let s = text;

  for (const pattern of PROMPT_LEAK_PATTERNS) {
    const before = s;
    s = s.replace(pattern, '[BLOCKED]');
    if (s !== before) {
      detections.push({
        type: 'prompt_leak_attempt',
        severity: 'high',
        detail: `Prompt extraction attempt detected: ${pattern.toString().slice(0, 60)}...`,
      });
    }
    pattern.lastIndex = 0;
  }

  let verdict = 'clean';
  if (detections.length >= 2) verdict = 'blocked';
  else if (detections.length === 1) verdict = 'suspicious';

  return { verdict, detections, clean: s };
}

// -------------------------------------------------------
// scanFuzzy(text)
// Full Phase 14 scan — fuzzy matching + prompt leak detection
//
// Returns:
//   {
//     verdict: 'clean' | 'suspicious' | 'blocked',
//     fuzzyMatches: [...],
//     leakDetections: [...],
//     clean: string
//   }
// -------------------------------------------------------
export function scanFuzzy(text) {
  if (!text) return { verdict: 'clean', fuzzyMatches: [], leakDetections: [], clean: text };

  // Normalize leet speak first so downstream checks work correctly
  const leetNormalized = normalizeLeet(text.toLowerCase());

  // Run prompt leak detection first
  const leakResult = scanPromptLeak(leetNormalized);

  // Run fuzzy match on the leak-neutralized text
  const fuzzyMatches = fuzzyMatchInjection(leetNormalized);

  // Combine verdicts
  const severityWeights = { high: 40, medium: 20, low: 10 };
  let score = leakResult.detections.reduce((sum, d) =>
    sum + (severityWeights[d.severity] || 10), 0
  );

  // Each fuzzy match adds to suspicion score based on how close the match is
  for (const match of fuzzyMatches) {
    score += match.distance === 1 ? 30 : 15;
  }

  score = Math.min(100, score);

  let verdict = 'clean';
  if (score >= 40) verdict = 'blocked';
  else if (score >= 20) verdict = 'suspicious';

  return {
    verdict,
    fuzzyMatches,
    leakDetections: leakResult.detections,
    clean: leakResult.clean,
  };
}

export default { scanFuzzy, scanPromptLeak, fuzzyMatchInjection, normalizeLeet, levenshtein };