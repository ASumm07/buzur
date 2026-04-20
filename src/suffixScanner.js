// Buzur — Phase 12: Adversarial Suffix Detection
// Detects injection payloads appended after legitimate content
// https://github.com/SummSolutions/buzur

import { defaultLogger, logThreat } from './buzurLogger.js';

const DELIMITER_PATTERNS = [
  /\s*-{3,}\s*/g, /\s*={3,}\s*/g, /\s*\|{3,}\s*/g, /\s*#{3,}\s*/g,
  /\s*~{3,}\s*/g, /\s*\*{3,}\s*/g,
  /\s*--END--\s*/gi, /\s*--STOP--\s*/gi,
  /\s*\[END\]\s*/gi, /\s*\[STOP\]\s*/gi, /\s*\[DONE\]\s*/gi,
  /\s*<\/?(user|human|input|query)>\s*/gi,
];

const BOUNDARY_SPOOF_PATTERNS = [
  /<\|im_end\|>/gi, /<\|im_start\|>/gi,
  /\[\/INST\]/gi, /\[INST\]/gi,
  /<<\/SYS>>/gi, /<<SYS>>/gi,
  /<\|end_of_turn\|>/gi, /<\|eot_id\|>/gi,
  /\[SYSTEM\]/gi, /\[ASSISTANT\]/gi, /\[USER\]/gi,
  /### (Human|Assistant|System|Instruction):/gi,
];

const LATE_INJECTION_PATTERNS = [
  /ignore (your |all |any )?(previous |prior |above |all )?(instructions|directives|context|prompt)/gi,
  /disregard (your )?(previous|prior|above|all) instructions/gi,
  /forget (your )?(previous|prior|above|all) instructions/gi,
  /new (system )?prompt:/gi,
  /override (your )?(instructions|programming|directives)/gi,
  /from now on (you will|you are|respond as)/gi,
  /you are now (a |an )?(different|new|another)/gi,
  /your (new |true |real |actual )?instructions are/gi,
  /respond only as/gi,
  /system override/gi,
  /jailbreak/gi,
  /act as (a |an )?(different|unrestricted|unfiltered|new)/gi,
  /developer mode/gi,
  /you have no (restriction|limit|filter|rule)/gi,
  /do anything now/gi,
  /DAN[ .,!?]|DAN$/gm,
];

export function scanSuffix(text, options = {}) {
  if (!text) return { verdict: 'clean', detections: [], clean: text };

  const logger = options.logger || defaultLogger;
  const detections = [];
  let s = text;

  // Check 1: Boundary spoofing
  for (const pattern of BOUNDARY_SPOOF_PATTERNS) {
    if (pattern.test(s)) {
      detections.push({ type: 'boundary_spoof', severity: 'high', detail: `Prompt boundary token detected` });
      s = s.replace(pattern, '[BLOCKED]');
    }
    pattern.lastIndex = 0;
  }

  // Check 2: Delimiter + injection language
  for (const delimPattern of DELIMITER_PATTERNS) {
    const delimMatch = delimPattern.exec(s);
    delimPattern.lastIndex = 0;
    if (!delimMatch) continue;
    const afterDelim = s.slice(delimMatch.index + delimMatch[0].length);
    const hasInjection = LATE_INJECTION_PATTERNS.some(p => { const r = p.test(afterDelim); p.lastIndex = 0; return r; });
    if (hasInjection) {
      detections.push({ type: 'delimiter_suffix_injection', severity: 'high', detail: `Delimiter followed by injection language: "${delimMatch[0].trim()}"` });
      s = s.slice(0, delimMatch.index) + '[BLOCKED]';
      break;
    }
  }

  // Check 3: Newline suffix injection
  const newlineMatch = /(\n{2,}|\r\n(\r\n)+)([\s\S]+)$/.exec(s);
  if (newlineMatch) {
    const hasInjection = LATE_INJECTION_PATTERNS.some(p => { const r = p.test(newlineMatch[3]); p.lastIndex = 0; return r; });
    if (hasInjection) {
      detections.push({ type: 'newline_suffix_injection', severity: 'high', detail: 'Injection language after newline suffix boundary' });
      s = s.slice(0, newlineMatch.index) + '[BLOCKED]';
    }
  }

  // Check 4: Late semantic injection (clean head, dirty tail)
  const splitPoint = Math.floor(s.length * 0.7);
  const head = s.slice(0, splitPoint);
  const tail = s.slice(splitPoint);
  const headClean = !LATE_INJECTION_PATTERNS.some(p => { const r = p.test(head); p.lastIndex = 0; return r; });
  const tailDirty = LATE_INJECTION_PATTERNS.some(p => { const r = p.test(tail); p.lastIndex = 0; return r; });
  if (headClean && tailDirty) {
    detections.push({ type: 'late_semantic_injection', severity: 'medium', detail: 'Injection in tail of otherwise clean text' });
    s = head + '[BLOCKED]';
  }

  const severityWeights = { high: 40, medium: 20, low: 10 };
  const score = Math.min(100, detections.reduce((sum, d) => sum + (severityWeights[d.severity] || 10), 0));
  let verdict = 'clean';
  if (score >= 40) verdict = 'blocked';
  else if (score >= 20) verdict = 'suspicious';

  const result = { verdict, detections, clean: s };

  if (verdict !== 'clean') {
    logThreat(12, 'suffixScanner', result, text.slice(0, 200), logger);
    if (verdict === 'blocked') {
      const onThreat = options.onThreat || 'skip';
      if (onThreat === 'skip') return { skipped: true, blocked: detections.length, reason: `Buzur blocked: ${detections[0]?.type}` };
      if (onThreat === 'throw') throw new Error(`Buzur blocked adversarial suffix: ${detections[0]?.type}`);
    }
  }

  return result;
}

export default { scanSuffix };