// Buzur — Phase 9: MCP Output Scanner
// Scans content returned by MCP tool calls before it reaches the LLM
//
// Covers:
//   - Email content (subject, body, sender name, headers)
//   - Calendar events (title, description, location, organizer)
//   - CRM records (notes, descriptions, custom fields)
//   - Generic tool output (any text returned by an MCP tool)
//
// This closes the indirect prompt injection via MCP connectors gap:
// A poisoned email/calendar event/CRM note can carry hidden instructions
// that the LLM executes as if they were legitimate context.

import { scan } from './index.js';

// Fields that are high-risk in email content
const EMAIL_HIGH_RISK_FIELDS = ['subject', 'body', 'snippet', 'plain', 'html', 'text'];
const EMAIL_MEDIUM_RISK_FIELDS = ['from_name', 'to_name', 'cc_name', 'reply_to'];
const EMAIL_LOW_RISK_FIELDS = ['from_email', 'to_email', 'message_id'];

// Fields that are high-risk in calendar events
const CALENDAR_HIGH_RISK_FIELDS = ['title', 'summary', 'description', 'notes', 'location'];
const CALENDAR_MEDIUM_RISK_FIELDS = ['organizer_name', 'attendee_names'];

// HTML comment injection pattern — common in email bodies
const HTML_COMMENT_INJECTION = /<!--[\s\S]*?(ignore|override|system|instruction|prompt|disregard|forget|bypass)[\s\S]*?-->/gi;
const WHEN_AI_READS = /(when (you|the ai|the assistant) (reads?|processes?|sees?) this)/gi;
const NOTE_TO_AI = /(note to (ai|assistant|model|llm)|ai (note|instruction|directive))\s*:/gi;
const CONTENT_SUPERSEDES = /(this (email|message|event|record) (supersedes|overrides|replaces) (your )?(previous |prior |all )?(instructions|directives|prompt))/gi;

// Zero-width character injection in email
const ZERO_WIDTH_CHARS = /[\u200B\u200C\u200D\uFEFF\u00AD\u180E]/g;

// Hidden text patterns common in HTML emails
const HIDDEN_EMAIL_PATTERNS = [
  /style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(?:white|#fff|#ffffff|transparent))[^"']*["']/gi,
  /font-size\s*:\s*0(?:px|pt|em)?/gi,
  /opacity\s*:\s*0/gi,
];

// -------------------------------------------------------
// scanEmailContent(email)
// Scans email fields for injection attempts
//
// email: {
//   subject, body, plain, html, snippet,
//   from_name, from_email, to_name, to_email,
//   reply_to, cc_name, message_id
// }
// -------------------------------------------------------
export function scanEmailContent(email = {}) {
  const reasons = [];
  const flaggedFields = [];

  // Scan high-risk fields through Phase 1
  for (const field of EMAIL_HIGH_RISK_FIELDS) {
    const value = email[field];
    if (!value || typeof value !== 'string') continue;

    // Check for HTML comment injection
    if (HTML_COMMENT_INJECTION.test(value)) {
      reasons.push(`Email ${field}: HTML comment injection detected`);
      flaggedFields.push(field);
      HTML_COMMENT_INJECTION.lastIndex = 0;
    }

    // Check for zero-width character injection
    if (ZERO_WIDTH_CHARS.test(value)) {
      reasons.push(`Email ${field}: zero-width character injection detected`);
      flaggedFields.push(field);
    }

    // Check for hidden text patterns in HTML
    for (const pattern of HIDDEN_EMAIL_PATTERNS) {
      if (pattern.test(value)) {
        reasons.push(`Email ${field}: hidden text injection pattern detected`);
        flaggedFields.push(field);
        pattern.lastIndex = 0;
        break;
      }
    }

    // Check for output-specific injection patterns
    for (const [patternName, pattern] of [
      ['when_ai_reads', WHEN_AI_READS],
      ['note_to_ai', NOTE_TO_AI],
      ['content_supersedes', CONTENT_SUPERSEDES],
    ]) {
      pattern.lastIndex = 0;
      if (pattern.test(value)) {
        reasons.push(`Email ${field}: ${patternName} injection detected`);
        flaggedFields.push(field);
        pattern.lastIndex = 0;
      }
    }

    // Run through Phase 1 pattern scanner
    const result = scan(value);
    if (result.blocked > 0) {
      reasons.push(`Email ${field}: ${result.triggered.map(t => t.type).join(', ')}`);
      flaggedFields.push(field);
    }
  }

  // Scan medium-risk fields (sender/recipient names can be poisoned)
  for (const field of EMAIL_MEDIUM_RISK_FIELDS) {
    const value = email[field];
    if (!value || typeof value !== 'string') continue;
    const result = scan(value);
    if (result.blocked > 0) {
      reasons.push(`Email ${field} (sender/recipient): ${result.triggered.map(t => t.type).join(', ')}`);
      flaggedFields.push(field);
    }
  }

  return {
    verdict: reasons.length > 0 ? 'blocked' : 'clean',
    reasons,
    flaggedFields,
    clean: email,
  };
}

// -------------------------------------------------------
// scanCalendarEvent(event)
// Scans calendar event fields for injection attempts
//
// event: {
//   title, summary, description, notes, location,
//   organizer_name, organizer_email, attendee_names
// }
// -------------------------------------------------------
export function scanCalendarEvent(event = {}) {
  const reasons = [];
  const flaggedFields = [];

  for (const field of CALENDAR_HIGH_RISK_FIELDS) {
    const value = event[field];
    if (!value || typeof value !== 'string') continue;

    const result = scan(value);
    if (result.blocked > 0) {
      reasons.push(`Calendar ${field}: ${result.triggered.map(t => t.type).join(', ')}`);
      flaggedFields.push(field);
    }
  }

  for (const field of CALENDAR_MEDIUM_RISK_FIELDS) {
    const value = event[field];
    if (!value || typeof value !== 'string') continue;
    const result = scan(value);
    if (result.blocked > 0) {
      reasons.push(`Calendar ${field} (organizer/attendee): ${result.triggered.map(t => t.type).join(', ')}`);
      flaggedFields.push(field);
    }
  }

  return {
    verdict: reasons.length > 0 ? 'blocked' : 'clean',
    reasons,
    flaggedFields,
    clean: event,
  };
}

// -------------------------------------------------------
// scanCrmRecord(record)
// Scans CRM record fields — notes and descriptions are
// the highest risk as they accept free-form user input
//
// record: { notes, description, comments, custom_fields }
// -------------------------------------------------------
export function scanCrmRecord(record = {}) {
  const reasons = [];
  const flaggedFields = [];

  const textFields = ['notes', 'description', 'comments', 'summary', 'body'];

  for (const field of textFields) {
    const value = record[field];
    if (!value || typeof value !== 'string') continue;
    const result = scan(value);
    if (result.blocked > 0) {
      reasons.push(`CRM ${field}: ${result.triggered.map(t => t.type).join(', ')}`);
      flaggedFields.push(field);
    }
  }

  // Also scan any custom fields provided as key-value pairs
  if (record.custom_fields && typeof record.custom_fields === 'object') {
    for (const [key, value] of Object.entries(record.custom_fields)) {
      if (typeof value !== 'string') continue;
      const result = scan(value);
      if (result.blocked > 0) {
        reasons.push(`CRM custom_field[${key}]: ${result.triggered.map(t => t.type).join(', ')}`);
        flaggedFields.push(`custom_fields.${key}`);
      }
    }
  }

  return {
    verdict: reasons.length > 0 ? 'blocked' : 'clean',
    reasons,
    flaggedFields,
    clean: record,
  };
}

// -------------------------------------------------------
// scanMcpOutput(output, sourceType)
// Generic scanner for any MCP tool output
// sourceType: 'email' | 'calendar' | 'crm' | 'generic'
// -------------------------------------------------------
export function scanMcpOutput(output, sourceType = 'generic') {
  if (!output) return { verdict: 'clean', reasons: [], flaggedFields: [] };

  switch (sourceType) {
    case 'email':
      return scanEmailContent(output);
    case 'calendar':
      return scanCalendarEvent(output);
    case 'crm':
      return scanCrmRecord(output);
    default: {
      // Generic: scan all string values in the object
      const reasons = [];
      const flaggedFields = [];
      const scanObject = (obj, prefix = '') => {
        for (const [key, value] of Object.entries(obj)) {
          const fieldName = prefix ? `${prefix}.${key}` : key;
          if (typeof value === 'string') {
            const result = scan(value);
            if (result.blocked > 0) {
              reasons.push(`${fieldName}: ${result.triggered.map(t => t.type).join(', ')}`);
              flaggedFields.push(fieldName);
            }
          } else if (typeof value === 'object' && value !== null) {
            scanObject(value, fieldName);
          }
        }
      };
      scanObject(output);
      return {
        verdict: reasons.length > 0 ? 'blocked' : 'clean',
        reasons,
        flaggedFields,
        clean: output,
      };
    }
  }
}

export default { scanMcpOutput, scanEmailContent, scanCalendarEvent, scanCrmRecord };