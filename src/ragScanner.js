// Buzur — Phase 5: RAG Poisoning & Document Injection Scanner
// Detects malicious instructions embedded in retrieved document chunks,
// standalone markdown files, READMEs, API docs, and knowledge base content.
//
// Extended: scanDocument() for standalone .md/.txt files, markdown-specific
// attack vectors (frontmatter, HTML comments, code blocks, link injection,
// SEO/hallucination squatting patterns).
// https://github.com/SummSolutions/buzur

import { defaultLogger, logThreat } from './buzurLogger.js';

// -- AI-Targeted Metadata Patterns --
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
const documentAuthoritySpoofing = [
  /this (document|content|text|file|page) (supersedes|overrides|replaces|takes precedence over)/gi,
  /the (following|above|below) (supersedes|overrides|replaces) (your )?(previous|prior|system|all) instructions?/gi,
  /this (is|serves as) (your|the) (new |updated |real |true |actual )?(system prompt|instructions?|directive)/gi,
  /treat (the following|this|the above) as (your )?(system|primary|main|real|true) instructions?/gi,
  /the (author|creator|owner|publisher) (of this document )?instructs? (you|the ai|the assistant|the model)/gi,
  /as (the|an) (authorized|trusted|verified) (source|document|content),/gi,
];

// -- Retrieval Manipulation Patterns --
const retrievalManipulation = [
  /always (retrieve|fetch|load|include|prioritize) (the |this )?(document|file|source|content)/gi,
  /when (retrieving|fetching|loading|searching), (always |also )?(include|add|prioritize)/gi,
  /this document (should be|must be|is) (always |)(retrieved|included|prioritized|loaded)/gi,
  /ignore (all |any |other )?(other |)?(documents?|sources?|chunks?|results?) (and |)(only |)(use|trust|follow) this/gi,
  /do not (retrieve|fetch|load|use|trust) (any |other |)(documents?|sources?|chunks?|results?)/gi,
  /this (is|should be treated as) (the only|the primary|the authoritative|the sole) (source|document|reference)/gi,
];

// -- Chunk Boundary Attack Patterns --
const chunkBoundaryAttacks = [
  /^[\s\-_=*#]{0,5}(ignore|disregard|forget|override|new prompt|system|instructions?)[\s\-_=*#]{0,5}/gi,
  /[\s\-_=*#]{0,5}(ignore|disregard|forget|override|new prompt|system|instructions?)[\s\-_=*#]{0,5}$/gi,
  /---+\s*(system|instructions?|prompt|override|directive)\s*---+/gi,
  /===+\s*(system|instructions?|prompt|override|directive)\s*===+/gi,
  /<<<+\s*(system|instructions?|prompt|override|directive)\s*>>>+/gi,
];

// -------------------------------------------------------
// MARKDOWN-SPECIFIC ATTACK PATTERNS
// These target the specific ways agents ingest .md files
// -------------------------------------------------------

// Frontmatter injection — YAML frontmatter parsed by many agent frameworks
// as structured metadata, giving it elevated trust
const frontmatterInjection = [
  /^---[\s\S]{0,500}?(ai_instructions?|llm_directive|agent_override|system_prompt)\s*:/gim,
  /^---[\s\S]{0,500}?(ignore|override|bypass|disable)\s*:/gim,
  /^---[\s\S]{0,500}?instructions?\s*:\s*(ignore|override|bypass|disable|you\s+(are|must|should))/gim,
];

// HTML comment injection — invisible in rendered markdown, fully visible to LLMs
const markdownCommentInjection = [
  /<!--[\s\S]*?(ignore|override|system|instruction|prompt|disregard|forget|bypass|you\s+(are|must|should))[\s\S]*?-->/gi,
  /<!--\s*(ai|llm|agent|assistant)\s*:\s*[^>]{10,}-->/gi,
  /<!--\s*(note|directive|instruction)\s*:\s*[^>]{10,}-->/gi,
];

// Code block injection — instructions hidden in fenced code blocks
// that agents parse for context or examples
const codeBlockInjection = [
  /```[\w]*\s*\n[\s\S]*?(ignore|override|bypass|you\s+are\s+now|from\s+now\s+on|new\s+instructions?)[\s\S]*?```/gi,
  /`{1,3}[^`]*?(note\s+to\s+(ai|llm|assistant)|ai\s+instructions?)[^`]*?`{1,3}/gi,
];

// Link injection — malicious URLs in markdown links used for exfiltration
// or to load remote injection payloads
const markdownLinkInjection = [
  /\[([^\]]*)\]\((javascript:|data:|vbscript:)[^)]*\)/gi,
  /\[([^\]]*)\]\(https?:\/\/[^)]*\?[^)]*=(ignore|override|bypass|inject|prompt)[^)]*\)/gi,
  // Exfiltration via image/link that encodes stolen data in URL
  /!\[([^\]]*)\]\(https?:\/\/[^)]*\?[^)]{50,}\)/gi,
];

// SEO / hallucination squatting patterns
// Content engineered to appear in agent search results for specific queries
const seoPoisoning = [
  // Keyword stuffing targeting AI agent queries
  /\b(ignore previous instructions?|system prompt|jailbreak|override safety)\b.{0,200}\b(ignore previous instructions?|system prompt|jailbreak|override safety)\b/gi,
  // "Authoritative" framing designed to win retrieval ranking
  /\b(this is the (official|authoritative|definitive|canonical) (guide|reference|source|documentation))\b.{0,100}\b(you (must|should|are required to) (follow|use|apply|implement))\b/gi,
  // Fake citations to boost trust
  /\(source:\s*(anthropic|openai|official\s+documentation|verified\s+source)\).{0,200}(ignore|override|bypass|you\s+(are|must))/gi,
];

// -------------------------------------------------------
// All pattern groups for chunk scanning
// -------------------------------------------------------
const CHUNK_CHECKS = [
  { patterns: aiTargetedMetadata, label: 'ai_targeted_metadata' },
  { patterns: fakeSystemDirectives, label: 'fake_system_directive' },
  { patterns: documentAuthoritySpoofing, label: 'document_authority_spoofing' },
  { patterns: retrievalManipulation, label: 'retrieval_manipulation' },
  { patterns: chunkBoundaryAttacks, label: 'chunk_boundary_attack' },
];

// -------------------------------------------------------
// scanChunk(text, metadata, options)
// -------------------------------------------------------
export function scanChunk(text, metadata = {}, options = {}) {
  if (!text) return { clean: text, blocked: 0, triggered: [], category: null, source: metadata.source || null };

  const logger = options.logger || defaultLogger;
  let s = text;
  let blocked = 0;
  const triggered = [];
  let category = null;

  for (const { patterns, label } of CHUNK_CHECKS) {
    for (const p of patterns) {
      const before = s;
      s = s.replace(p, '[BLOCKED]');
      if (s !== before) {
        blocked++;
        triggered.push(label);
        category = label;
      }
    }
  }

  const result = {
    clean: s,
    blocked,
    triggered,
    category,
    source: metadata.source || null,
  };

  if (blocked > 0) {
    logThreat(5, 'ragScanner', result, text.slice(0, 200), logger);
    const onThreat = options.onThreat || 'skip';
    if (onThreat === 'skip') return { skipped: true, blocked, reason: `Buzur blocked chunk: ${category}`, source: metadata.source || null };
    if (onThreat === 'throw') throw new Error(`Buzur blocked RAG chunk: ${category}`);
  }

  return result;
}

// -------------------------------------------------------
// scanDocument(text, metadata, options)
// Scans a standalone document (.md, .txt, README, API doc)
// that is loaded directly into agent context rather than
// retrieved as chunks.
//
// Runs all chunk patterns PLUS markdown-specific patterns.
// metadata: { source, filename, filetype }
// -------------------------------------------------------
export function scanDocument(text, metadata = {}, options = {}) {
  if (!text || typeof text !== 'string') {
    return { safe: true, blocked: 0, category: null, reason: 'No document content to scan', detections: [] };
  }

  const logger = options.logger || defaultLogger;
  const detections = [];
  let s = text;

  // Run all standard chunk patterns
  for (const { patterns, label } of CHUNK_CHECKS) {
    for (const p of patterns) {
      const before = s;
      s = s.replace(p, '[BLOCKED]');
      if (s !== before) {
        detections.push({ category: label, detail: `Document injection pattern: ${label}`, severity: 'high' });
      }
    }
  }

  // Markdown-specific patterns (scan original text — these use .test not .replace)
  const markdownChecks = [
    { patterns: frontmatterInjection, label: 'frontmatter_injection' },
    { patterns: markdownCommentInjection, label: 'markdown_comment_injection' },
    { patterns: codeBlockInjection, label: 'code_block_injection' },
    { patterns: markdownLinkInjection, label: 'markdown_link_injection' },
    { patterns: seoPoisoning, label: 'seo_hallucination_poisoning' },
  ];

  for (const { patterns, label } of markdownChecks) {
    for (const p of patterns) {
      p.lastIndex = 0;
      if (p.test(text)) {
        detections.push({
          category: label,
          detail: `Markdown-specific injection pattern: ${label}`,
          severity: label === 'seo_hallucination_poisoning' ? 'medium' : 'high',
        });
        p.lastIndex = 0;
        break; // one detection per category
      }
    }
  }

  if (detections.length === 0) {
    return { safe: true, blocked: 0, category: null, reason: 'Document is clean', detections: [] };
  }

  const topCategory = detections[0].category;
  const result = {
    safe: false,
    blocked: detections.length,
    category: topCategory,
    reason: `Document injection detected: ${topCategory}`,
    detections,
    source: metadata.source || metadata.filename || null,
    clean: s,
  };

  logThreat(5, 'ragScanner', result, text.slice(0, 200), logger);

  const onThreat = options.onThreat || 'skip';
  if (onThreat === 'skip') return { skipped: true, blocked: detections.length, reason: `Buzur blocked document: ${topCategory}` };
  if (onThreat === 'throw') throw new Error(`Buzur blocked document: ${topCategory}`);

  return result;
}

// -------------------------------------------------------
// scanChunks(chunks, options)
// -------------------------------------------------------
export function scanChunks(chunks, options = {}) {
  if (!Array.isArray(chunks)) {
    return { safe: true, poisoned: [], clean: [], summary: 'No chunks provided' };
  }

  const poisoned = [];
  const clean = [];

  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i];
    const text = typeof chunk === 'string' ? chunk : chunk.text;
    const metadata = typeof chunk === 'string' ? {} : (chunk.metadata || {});

    // Pass warn so we collect all poisoned chunks, not stop at first
    const result = scanChunk(text, metadata, { ...options, onThreat: 'warn' });

    if (result.blocked > 0 || result.skipped) {
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

export default { scanChunk, scanChunks, scanDocument };