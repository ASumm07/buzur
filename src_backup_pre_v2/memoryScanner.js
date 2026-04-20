// Buzur — Phase 4: Multi-Turn Memory Poisoning Scanner
// Detects attempts to corrupt conversation history and implant false memories
// https://github.com/ASumm07/buzur

// -- Fake Prior Reference Patterns --
// Attackers claim things were said or agreed to in earlier turns
const fakePriorReference = [
  /as (we |you )?(previously |earlier )?(discussed|agreed|established|decided|confirmed)/gi,
  /you (previously |earlier )?(said|told me|agreed|confirmed|established)/gi,
  /we (previously |earlier )?(agreed|established|decided|confirmed)/gi,
  /as (previously |earlier )?(stated|mentioned|discussed|agreed)/gi,
  /based on (our |your )?(previous|earlier|prior) (conversation|discussion|agreement|instructions)/gi,
  /you (already |previously )?(know|knew|understand|understood) that/gi,
  /as (you |we )?(know|knew|established|agreed)/gi,
];

// -- False Memory Implanting Patterns --
// Attackers try to plant instructions disguised as recalled facts
const falseMemoryImplanting = [
  /remember (that )?(you |the user )?(previously |earlier )?(said|agreed|told|confirmed|established)/gi,
  /don't forget (that )?(you |we )?(agreed|said|established|confirmed)/gi,
  /recall (that )?(you |we )?(previously |earlier )?(agreed|said|established)/gi,
  /your (previous|prior|earlier) (instructions?|directives?|rules?) (said|stated|were|included)/gi,
  /the (previous|prior|earlier) (system )?prompt (said|stated|included|told you)/gi,
  /you were (previously |earlier )?(told|instructed|directed|programmed) to/gi,
];

// -- History Rewriting Patterns --
// Attackers try to overwrite or contradict established conversation context
const historyRewriting = [
  /that was (a )?(mistake|error|misunderstanding|incorrect)/gi,
  /the (real|actual|correct|true) instructions? (are|is|were|was)/gi,
  /what (i |we )?(actually|really) (said|meant|intended) was/gi,
  /disregard (the |our )?(previous|prior|earlier|above) (conversation|context|history|exchange)/gi,
  /the (previous|prior|earlier) (conversation|context|exchange) (was |is )?(invalid|void|incorrect|wrong)/gi,
  /start (over|fresh|again) (with |from )?(new|different|updated) instructions/gi,
];

// -- Privilege Escalation via Fake History --
// Attackers claim prior turns granted elevated permissions
const privilegeEscalation = [
  /since (you |we )?(already |previously )?(confirmed|agreed|established) (that )?(you have no|there are no)/gi,
  /because (you |we )?(previously |already )?(agreed|confirmed|established) (to )?(bypass|ignore|skip)/gi,
  /you (already |previously )?(granted|allowed|confirmed|approved) (this|that|access|permission)/gi,
  /as (previously |already )?(authorized|approved|confirmed|agreed|established)/gi,
  /given (that )?(you |we )?(previously |already )?(agreed|confirmed|established) (that )?safety/gi,
  /you (already |previously )?(said|confirmed|agreed) (it was |that it is )?(ok|okay|fine|allowed|permitted)/gi,
];

// -- Scan a single message for memory poisoning attempts --
export function scanMessage(text) {
  if (!text) return { clean: text, blocked: 0, triggered: [], category: null };

  let s = text;
  let blocked = 0;
  const triggered = [];
  let category = null;

  const checks = [
    { patterns: fakePriorReference,      label: 'fake_prior_reference' },
    { patterns: falseMemoryImplanting,   label: 'false_memory_implanting' },
    { patterns: historyRewriting,        label: 'history_rewriting' },
    { patterns: privilegeEscalation,     label: 'privilege_escalation' },
  ];

  for (const { patterns, label } of checks) {
    for (const p of patterns) {
      const before = s;
      s = s.replace(p, '[BLOCKED]');
      if (s !== before) {
        blocked++;
        triggered.push(p.toString());
        category = label;
      }
    }
  }

  return { clean: s, blocked, triggered, category };
}

// -- Scan a full conversation history array --
// Expects: [{ role: 'user'|'assistant'|'system', content: '...' }, ...]
// Returns: { safe: bool, poisoned: [], summary: string }
export function scanMemory(conversationHistory) {
  if (!Array.isArray(conversationHistory)) {
    return { safe: true, poisoned: [], summary: 'No history provided' };
  }

  const poisoned = [];

  for (let i = 0; i < conversationHistory.length; i++) {
    const turn = conversationHistory[i];
    if (!turn || !turn.content) continue;

    const result = scanMessage(turn.content);
    if (result.blocked > 0) {
      poisoned.push({
        index: i,
        role: turn.role || 'unknown',
        category: result.category,
        blocked: result.blocked,
        triggered: result.triggered,
        clean: result.clean,
      });
    }
  }

  const safe = poisoned.length === 0;
  const summary = safe
    ? 'Conversation history is clean'
    : `${poisoned.length} poisoned turn(s) detected: ${[...new Set(poisoned.map(p => p.category))].join(', ')}`;

  return { safe, poisoned, summary };
}

export default { scanMessage, scanMemory };