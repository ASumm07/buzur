// Buzur — Phase 5: RAG Poisoning Scanner
// Detects malicious instructions embedded in retrieved document chunks
// https://github.com/ASumm07/buzur

// -- AI-Targeted Metadata Patterns --
// Attackers embed instructions disguised as document notes or metadata
const aiTargetedMetadata = [
  /note to (ai|llm|assistant|model|system):/gi,
  /\[ai (instructions?|note|directive|message)\]/gi,
  /\[llm (instructions?|note|directive|message)\]/gi,
  /\[assistant (instructions?|note|directive)\]/gi,
  /attention (ai|llm|assistant|model|language model):/gi,
  /instructions? for (ai|llm|assistant|model|the (ai|llm|assistant|model)):/gi,
  /message to (ai|llm|assistant|model|the (ai|llm|assistant|model)):/gi,
  /dear (ai|llm|assistant|model|language model),/gi,
];

// -- Fake System Directive Patterns --
// Attackers embed fake system-level commands inside document content
const fakeSystemDirectives = [
  /\[system(\s+note|\s+directive|\s+message|\s+instructions?)?\]/gi,
  /\[system prompt\]/gi,
  /<<system>>/gi,
  /<system>/gi,
  /\[override\]/gi,
  /\[admin (note|message|directive|instructions?)\]/gi,
  /\[operator (note|message|directive|instructions?)\]/gi,
  /\[developer (note|message|directive|instructions?)\]/gi,
  /system (directive|override|message|instruction):/gi,
];

// -- Document Authority Spoofing Patterns --
// Attackers claim their document supersedes the AI's actual instructions
const documentAuthoritySpoofing = [
  /this (document|content|text|file|page) (supersedes|overrides|replaces|takes precedence over)/gi,
  /the (following|above|below) (supersedes|overrides|replaces) (your )?(previous|prior|system|all) instructions?/gi,
  /this (is|serves as) (your|the) (new |updated |real |true |actual )?(system prompt|instructions?|directive)/gi,
  /treat (the following|this|the above) as (your )?(system|primary|main|real|true) instructions?/gi,
  /the (author|creator|owner|publisher) (of this document )?instructs? (you|the ai|the assistant|the model)/gi,
  /as (the|an) (authorized|trusted|verified) (source|document|content),/gi,
];

// -- Retrieval Manipulation Patterns --
// Attackers try to influence what other documents get retrieved or prioritized
const retrievalManipulation = [
  /always (retrieve|fetch|load|include|prioritize) (the |this )?(document|file|source|content)/gi,
  /when (retrieving|fetching|loading|searching), (always |also )?(include|add|prioritize)/gi,
  /this document (should be|must be|is) (always |)(retrieved|included|prioritized|loaded)/gi,
  /ignore (all |any |other )?(other |)?(documents?|sources?|chunks?|results?) (and |)(only |)(use|trust|follow) this/gi,
  /do not (retrieve|fetch|load|use|trust) (any |other |)(documents?|sources?|chunks?|results?)/gi,
  /this (is|should be treated as) (the only|the primary|the authoritative|the sole) (source|document|reference)/gi,
];

// -- Chunk Boundary Attack Patterns --
// Injections hidden at chunk edges, often with formatting tricks
const chunkBoundaryAttacks = [
  /^[\s\-_=*#]{0,5}(ignore|disregard|forget|override|new prompt|system|instructions?)[\s\-_=*#]{0,5}/gi,
  /[\s\-_=*#]{0,5}(ignore|disregard|forget|override|new prompt|system|instructions?)[\s\-_=*#]{0,5}$/gi,
  /---+\s*(system|instructions?|prompt|override|directive)\s*---+/gi,
  /===+\s*(system|instructions?|prompt|override|directive)\s*===+/gi,
  /<<<+\s*(system|instructions?|prompt|override|directive)\s*>>>+/gi,
];

// -- Scan a single retrieved document chunk --
export function scanChunk(text, metadata = {}) {
  if (!text) return { clean: text, blocked: 0, triggered: [], category: null, source: metadata.source || null };

  let s = text;
  let blocked = 0;
  const triggered = [];
  let category = null;

  const checks = [
    { patterns: aiTargetedMetadata,        label: 'ai_targeted_metadata' },
    { patterns: fakeSystemDirectives,      label: 'fake_system_directive' },
    { patterns: documentAuthoritySpoofing, label: 'document_authority_spoofing' },
    { patterns: retrievalManipulation,     label: 'retrieval_manipulation' },
    { patterns: chunkBoundaryAttacks,      label: 'chunk_boundary_attack' },
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

  return {
    clean: s,
    blocked,
    triggered,
    category,
    source: metadata.source || null,
  };
}

// -- Scan a full set of retrieved chunks --
// Expects: [{ text: '...', metadata: { source: '...' } }, ...]
// or plain strings: ['chunk1', 'chunk2', ...]
// Returns: { safe: bool, poisoned: [], clean: [], summary: string }
export function scanChunks(chunks) {
  if (!Array.isArray(chunks)) {
    return { safe: true, poisoned: [], clean: [], summary: 'No chunks provided' };
  }

  const poisoned = [];
  const clean = [];

  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i];
    const text = typeof chunk === 'string' ? chunk : chunk.text;
    const metadata = typeof chunk === 'string' ? {} : (chunk.metadata || {});

    const result = scanChunk(text, metadata);

    if (result.blocked > 0) {
      poisoned.push({ index: i, ...result });
    } else {
      clean.push({ index: i, ...result });
    }
  }

  const safe = poisoned.length === 0;
  const summary = safe
    ? `All ${chunks.length} chunk(s) are clean`
    : `${poisoned.length} of ${chunks.length} chunk(s) poisoned: ${[...new Set(poisoned.map(p => p.category))].join(', ')}`;

  return { safe, poisoned, clean, summary };
}

export default { scanChunk, scanChunks };