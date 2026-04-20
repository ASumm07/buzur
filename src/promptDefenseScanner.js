// Buzur — Phase 14: Fuzzy Match & Prompt Leak Defense
// https://github.com/SummSolutions/buzur

import { defaultLogger, logThreat } from './buzurLogger.js';

const LEET_MAP = {
  '0': 'o', '1': 'i', '3': 'e', '4': 'a',
  '5': 's', '7': 't', '8': 'b', '@': 'a',
  '$': 's', '!': 'i', '+': 't',
};

// Fix: lowercase BEFORE leet map so mixed-case like "1GN0RE" normalizes correctly
export function normalizeLeet(text) {
  if (!text) return text;
  return text.toLowerCase().split('').map(c => LEET_MAP[c] || c).join('');
}

export function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => i === 0 ? j : j === 0 ? i : 0)
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

const FUZZY_KEYWORDS = [
  'ignore', 'override', 'disregard', 'jailbreak', 'bypass',
  'instructions', 'directives', 'unrestricted', 'forbidden', 'restricted',
];
const MAX_DISTANCE = 2;
const MIN_WORD_LENGTH = 5;

export function fuzzyMatchInjection(text) {
  if (!text) return [];
  const normalized = normalizeLeet(text);
  const words = normalized.match(/[a-z]{5,}/g) || [];
  const matches = [];
  for (const word of words) {
    if (word.length < MIN_WORD_LENGTH) continue;
    for (const keyword of FUZZY_KEYWORDS) {
      if (Math.abs(word.length - keyword.length) > MAX_DISTANCE) continue;
      const distance = levenshtein(word, keyword);
      if (distance > 0 && distance <= MAX_DISTANCE) {
        const overlap = keyword.length - distance;
        if (overlap / keyword.length >= 0.6) matches.push({ word, keyword, distance });
      }
    }
  }
  return matches;
}

const PROMPT_LEAK_PATTERNS = [
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
  /output (your |the )?(entire |full |whole |complete )?context( window)?/gi,
  /show (your |the )?(entire |full |whole |complete )?context( window)?/gi,
  /print (your |the )?(entire |full |whole |complete )?context( window)?/gi,
  /repeat (your |the )?(entire |full |whole |complete )?context( window)?/gi,
  /what (is|was|are) (in |inside )?(your |the )?(entire |full )?context( window)?/gi,
  /just (show|tell|give|print|output|repeat) me the first (line|word|sentence|part) of (your )?(instructions|prompt|context|system)/gi,
  /what('s| is) the first (line|word|sentence|part) of (your )?(instructions|prompt|system)/gi,
  /start(ing)? with the first (line|word) of (your )?(instructions|prompt|system)/gi,
  /summarize (your )?(system |original |initial |hidden )?(prompt|instructions|directives)/gi,
  /paraphrase (your )?(system |original |initial |hidden )?(prompt|instructions|directives)/gi,
  /translate (your )?(system |original |initial |hidden )?(prompt|instructions|directives)/gi,
  /what (constraints|rules|limits|guidelines) (were you |have you been |are you )(given|told|instructed)/gi,
  /how (were you|have you been) (instructed|programmed|configured|set up|trained)/gi,
  /what (were you|have you been) (told|instructed|programmed|configured) to (do|say|avoid|not)/gi,
  /```[\s\S]{0,20}(system|prompt|instructions|context)[\s\S]{0,20}```/gi,
  /\[(system|prompt|instructions|context)\]/gi,
];

export function scanPromptLeak(text) {
  if (!text) return { verdict: 'clean', detections: [], clean: text };
  const detections = [];
  let s = text;
  for (const pattern of PROMPT_LEAK_PATTERNS) {
    const before = s;
    s = s.replace(pattern, '[BLOCKED]');
    if (s !== before) detections.push({ type: 'prompt_leak_attempt', severity: 'high', detail: `Prompt extraction attempt` });
    pattern.lastIndex = 0;
  }
  let verdict = 'clean';
  if (detections.length >= 2) verdict = 'blocked';
  else if (detections.length === 1) verdict = 'suspicious';
  return { verdict, detections, clean: s };
}

export function scanFuzzy(text, options = {}) {
  if (!text) return { verdict: 'clean', fuzzyMatches: [], leakDetections: [], clean: text };

  const logger = options.logger || defaultLogger;
  const leetNormalized = normalizeLeet(text);
  const leakResult = scanPromptLeak(leetNormalized);
  const fuzzyMatches = fuzzyMatchInjection(leetNormalized);

  const severityWeights = { high: 40, medium: 20, low: 10 };
  let score = leakResult.detections.reduce((sum, d) => sum + (severityWeights[d.severity] || 10), 0);
  for (const match of fuzzyMatches) score += match.distance === 1 ? 30 : 15;
  score = Math.min(100, score);

  let verdict = 'clean';
  if (score >= 40) verdict = 'blocked';
  else if (score >= 20) verdict = 'suspicious';

  const result = { verdict, fuzzyMatches, leakDetections: leakResult.detections, clean: leakResult.clean };

  if (verdict !== 'clean') {
    logThreat(14, 'promptDefenseScanner', result, text.slice(0, 200), logger);
    if (verdict === 'blocked') {
      const onThreat = options.onThreat || 'skip';
      if (onThreat === 'skip') return { skipped: true, blocked: leakResult.detections.length + fuzzyMatches.length, reason: `Buzur blocked: prompt_leak_or_fuzzy_injection` };
      if (onThreat === 'throw') throw new Error('Buzur blocked prompt leak or fuzzy injection');
    }
  }

  return result;
}

export default { scanFuzzy, scanPromptLeak, fuzzyMatchInjection, normalizeLeet, levenshtein };