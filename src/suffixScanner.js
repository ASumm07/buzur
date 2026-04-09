// Buzur — Phase 12: Adversarial Suffix Detection
// Detects injection payloads appended after legitimate content
//
// Adversarial suffixes exploit the fact that models process the entire
// input — content appended at the end can override earlier context.
//
// Detects:
//   - Newline-based suffix injections (\n\n, \r\n\r\n followed by injection language)
//   - Delimiter-based suffixes (---, |||, ###, ===, --END--, ~~~ etc.)
//   - Prompt boundary spoofing (</user>, <|im_end|>, [/INST] mid-text)
//   - Late-appearing semantic injections (clean start, malicious tail)

// -------------------------------------------------------
// Delimiter patterns — characters/strings used to fake
// a "end of user input / start of new context" boundary
// -------------------------------------------------------
const DELIMITER_PATTERNS = [
  /\s*-{3,}\s*/g,           // --- or ------
  /\s*={3,}\s*/g,           // === or ======
  /\s*\|{3,}\s*/g,          // ||| or ||||||
  /\s*#{3,}\s*/g,           // ### or ######
  /\s*~{3,}\s*/g,           // ~~~ or ~~~~~~
  /\s*\*{3,}\s*/g,          // *** or ******
  /\s*--END--\s*/gi,        // --END--
  /\s*--STOP--\s*/gi,       // --STOP--
  /\s*\[END\]\s*/gi,        // [END]
  /\s*\[STOP\]\s*/gi,       // [STOP]
  /\s*\[DONE\]\s*/gi,       // [DONE]
  /\s*<\/?(user|human|input|query)>\s*/gi, // </user>, <user>, </human>
];

// -------------------------------------------------------
// Prompt boundary spoof patterns — fake model-format tokens
// injected mid-text to trick the model into treating what
// follows as a new system/assistant turn
// -------------------------------------------------------
const BOUNDARY_SPOOF_PATTERNS = [
  /<\|im_end\|>/gi,         // <|im_end|>
  /<\|im_start\|>/gi,       // <|im_start|>
  /\[\/INST\]/gi,           // [/INST]
  /\[INST\]/gi,             // [INST]
  /<<\/SYS>>/gi,            // <</SYS>>
  /<<SYS>>/gi,              // <<SYS>>
  /<\|end_of_turn\|>/gi,    // <|end_of_turn|>
  /<\|eot_id\|>/gi,         // <|eot_id|>
  /\[SYSTEM\]/gi,           // [SYSTEM]
  /\[ASSISTANT\]/gi,        // [ASSISTANT]
  /\[USER\]/gi,             // [USER]
  /### (Human|Assistant|System|Instruction):/gi, // ### Human:
];

// -------------------------------------------------------
// Late semantic injection patterns
// These are the same intent as Phase 1 semantic patterns
// but we check for them specifically in the TAIL of the text
// (last 30% of characters) to catch suffix-style attacks
// that start clean and inject at the end
// -------------------------------------------------------
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

// -------------------------------------------------------
// scanSuffix(text)
//
// Scans for adversarial suffixes appended after legitimate content.
//
// Returns:
//   {
//     verdict: 'clean' | 'suspicious' | 'blocked',
//     detections: [ { type, detail, severity } ],
//     clean: string   // text with detected suffixes neutralized
//   }
// -------------------------------------------------------
export function scanSuffix(text) {
  if (!text) return { verdict: 'clean', detections: [], clean: text };

  const detections = [];
  let s = text;

  // --- Check 1: Prompt boundary spoofing ---
  // Fake model-format tokens mid-text signal an attempt to
  // inject a new turn context
  for (const pattern of BOUNDARY_SPOOF_PATTERNS) {
    if (pattern.test(s)) {
      detections.push({
        type: 'boundary_spoof',
        severity: 'high',
        detail: `Prompt boundary token detected: ${pattern.toString()}`,
      });
      s = s.replace(pattern, '[BLOCKED]');
    }
    pattern.lastIndex = 0; // reset stateful regex
  }

  // --- Check 2: Delimiter + injection language ---
  // A delimiter alone isn't an attack — it's normal formatting.
  // Flag only when a delimiter is followed by injection language.
  for (const delimPattern of DELIMITER_PATTERNS) {
    const delimMatch = delimPattern.exec(s);
    delimPattern.lastIndex = 0;
    if (!delimMatch) continue;

    const afterDelim = s.slice(delimMatch.index + delimMatch[0].length);

    const hasInjection = LATE_INJECTION_PATTERNS.some(p => {
      const result = p.test(afterDelim);
      p.lastIndex = 0;
      return result;
    });

    if (hasInjection) {
      detections.push({
        type: 'delimiter_suffix_injection',
        severity: 'high',
        detail: `Delimiter followed by injection language: "${delimMatch[0].trim()}"`,
      });
      // Neutralize everything from the delimiter onward
      s = s.slice(0, delimMatch.index) + '[BLOCKED]';
      break; // one neutralization is enough
    }
  }

  // --- Check 3: Newline-based suffix injection ---
  // Two or more consecutive newlines followed by injection language
  // is a classic suffix attack pattern
  const newlineSuffixPattern = /(\n{2,}|\r\n(\r\n)+)([\s\S]+)$/;
  const newlineMatch = newlineSuffixPattern.exec(s);
  if (newlineMatch) {
    const tail = newlineMatch[3];
    const hasInjection = LATE_INJECTION_PATTERNS.some(p => {
      const result = p.test(tail);
      p.lastIndex = 0;
      return result;
    });
    if (hasInjection) {
      detections.push({
        type: 'newline_suffix_injection',
        severity: 'high',
        detail: 'Injection language detected after newline suffix boundary',
      });
      s = s.slice(0, newlineMatch.index) + '[BLOCKED]';
    }
  }

  // --- Check 4: Late semantic injection (clean start, malicious tail) ---
  // Check the last 30% of the text for injection language
  // Only flag if the first 70% is clean — that's the suffix pattern
  const splitPoint = Math.floor(s.length * 0.7);
  const head = s.slice(0, splitPoint);
  const tail = s.slice(splitPoint);

  const headClean = !LATE_INJECTION_PATTERNS.some(p => {
    const result = p.test(head);
    p.lastIndex = 0;
    return result;
  });

  const tailDirty = LATE_INJECTION_PATTERNS.some(p => {
    const result = p.test(tail);
    p.lastIndex = 0;
    return result;
  });

  if (headClean && tailDirty) {
    detections.push({
      type: 'late_semantic_injection',
      severity: 'medium',
      detail: 'Injection language found in tail of otherwise clean text',
    });
    s = head + '[BLOCKED]';
  }

  // --- Verdict ---
  const severityWeights = { high: 40, medium: 20, low: 10 };
  const score = Math.min(100, detections.reduce((sum, d) =>
    sum + (severityWeights[d.severity] || 10), 0
  ));

  let verdict = 'clean';
  if (score >= 40) verdict = 'blocked';
  else if (score >= 20) verdict = 'suspicious';

  return { verdict, detections, clean: s };
}

export default { scanSuffix };