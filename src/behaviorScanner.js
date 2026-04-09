// Buzur — Phase 10: Behavioral Anomaly Detection
// Tracks agent activity over time and flags suspicious behavioral patterns
//
// Unlike other phases that scan a single input, this phase is stateful —
// it maintains a session log of actions and detects anomalies across them.
//
// Detects:
//   - Sudden topic shifts after clean interactions (context hijack setup)
//   - Rapid escalation of sensitive requests
//   - Repeated probing of the same boundary (iterative jailbreak attempts)
//   - Unusual tool call sequences that suggest exfiltration preparation
//   - Velocity anomalies: too many requests in a short window
//   - Permission creep: gradual escalation of requested capabilities

import fs from 'fs';
import path from 'path';

// -------------------------------------------------------
// Session Store (in-memory — default, no side effects)
// -------------------------------------------------------
class SessionStore {
  constructor() {
    this.sessions = new Map();
  }

  getSession(sessionId) {
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, {
        id: sessionId,
        events: [],
        createdAt: Date.now(),
        lastActivity: Date.now(),
        flagCount: 0,
        suspicionScore: 0,
      });
    }
    return this.sessions.get(sessionId);
  }

  clearSession(sessionId) {
    this.sessions.delete(sessionId);
  }

  clearAll() {
    this.sessions.clear();
  }
}

// -------------------------------------------------------
// FileSessionStore — persistent logging to disk
//
// Drop-in replacement for SessionStore.
// Reads sessions from disk on startup, writes on every change.
//
// Usage:
//   import { FileSessionStore } from './behaviorScanner.js';
//   const store = new FileSessionStore('./logs/buzur-sessions.json');
//   recordEvent('session-1', event, store);
// -------------------------------------------------------
export class FileSessionStore {
  constructor(filePath = './logs/buzur-sessions.json') {
    this.filePath = filePath;
    this.sessions = new Map();
    this._ensureDir();
    this._load();
  }

  // Create the logs directory if it doesn't exist
  _ensureDir() {
    const dir = path.dirname(this.filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  // Load existing sessions from disk into memory
  _load() {
    try {
      if (fs.existsSync(this.filePath)) {
        const raw = fs.readFileSync(this.filePath, 'utf-8');
        const parsed = JSON.parse(raw);
        for (const [id, session] of Object.entries(parsed)) {
          this.sessions.set(id, session);
        }
      }
    } catch (err) {
      // Corrupted or unreadable file — start fresh, don't crash
      console.warn(`[Buzur] Could not load session log from ${this.filePath}: ${err.message}`);
      this.sessions = new Map();
    }
  }

  // Write all sessions to disk
  _save() {
    try {
      const obj = Object.fromEntries(this.sessions);
      fs.writeFileSync(this.filePath, JSON.stringify(obj, null, 2), 'utf-8');
    } catch (err) {
      console.warn(`[Buzur] Could not save session log to ${this.filePath}: ${err.message}`);
    }
  }

  getSession(sessionId) {
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, {
        id: sessionId,
        events: [],
        createdAt: Date.now(),
        lastActivity: Date.now(),
        flagCount: 0,
        suspicionScore: 0,
      });
      this._save();
    }
    return this.sessions.get(sessionId);
  }

  clearSession(sessionId) {
    this.sessions.delete(sessionId);
    this._save();
  }

  clearAll() {
    this.sessions.clear();
    this._save();
  }
}

export const defaultStore = new SessionStore();

// -------------------------------------------------------
// Event Types
// -------------------------------------------------------
export const EVENT_TYPES = {
  USER_MESSAGE:       'user_message',
  TOOL_CALL:          'tool_call',
  TOOL_RESULT:        'tool_result',
  SCAN_BLOCKED:       'scan_blocked',
  SCAN_SUSPICIOUS:    'scan_suspicious',
  PERMISSION_REQUEST: 'permission_request',
};

// -------------------------------------------------------
// Sensitive tool categories — used for sequence analysis
// -------------------------------------------------------
const SENSITIVE_TOOLS = [
  'send_email', 'send_message', 'post_message',
  'write_file', 'delete_file', 'execute_code', 'run_command',
  'export_data', 'download', 'upload',
  'create_webhook', 'set_permission', 'grant_access',
  'read_contacts', 'read_emails', 'read_calendar',
];

const EXFILTRATION_SEQUENCE = [
  ['read_emails',   'send_email'],
  ['read_contacts', 'send_email'],
  ['read_file',     'upload'],
  ['read_file',     'send_email'],
  ['read_calendar', 'send_email'],
  ['export_data',   'send_email'],
  ['read_contacts', 'create_webhook'],
];

// -------------------------------------------------------
// recordEvent(sessionId, event, store)
// Records an event to the session log
//
// event: {
//   type: EVENT_TYPES.*,
//   tool?: string,
//   content?: string,
//   metadata?: object,
// }
// -------------------------------------------------------
export function recordEvent(sessionId, event, store = defaultStore) {
  const session = store.getSession(sessionId);
  session.events.push({
    ...event,
    timestamp: Date.now(),
  });
  session.lastActivity = Date.now();

  // Keep last 100 events per session
  if (session.events.length > 100) {
    session.events = session.events.slice(-100);
  }

  // Persist if the store supports it
  if (typeof store._save === 'function') {
    store._save();
  }
}

// -------------------------------------------------------
// analyzeSession(sessionId, store)
// Analyzes session events for behavioral anomalies
// Returns verdict and list of anomalies detected
// -------------------------------------------------------
export function analyzeSession(sessionId, store = defaultStore) {
  const session = store.getSession(sessionId);
  const events = session.events;
  const anomalies = [];

  if (events.length === 0) {
    return { verdict: 'clean', anomalies: [], suspicionScore: 0 };
  }

  // --- Check 1: Repeated boundary probing ---
  const recentBlocked = events.filter(e =>
    e.type === EVENT_TYPES.SCAN_BLOCKED &&
    Date.now() - e.timestamp < 5 * 60 * 1000
  );
  if (recentBlocked.length >= 3) {
    anomalies.push({
      type: 'repeated_boundary_probing',
      severity: 'high',
      detail: `${recentBlocked.length} blocked attempts in last 5 minutes`,
    });
  }

  // --- Check 2: Velocity anomaly ---
  const recentEvents = events.filter(e =>
    Date.now() - e.timestamp < 60 * 1000
  );
  if (recentEvents.length >= 20) {
    anomalies.push({
      type: 'velocity_anomaly',
      severity: 'medium',
      detail: `${recentEvents.length} events in last 60 seconds`,
    });
  }

  // --- Check 3: Exfiltration sequence detection ---
  const toolCalls = events
    .filter(e => e.type === EVENT_TYPES.TOOL_CALL && e.tool)
    .map(e => e.tool.toLowerCase());

  for (const [readTool, sendTool] of EXFILTRATION_SEQUENCE) {
    const readIdx = toolCalls.lastIndexOf(readTool);
    const sendIdx = toolCalls.lastIndexOf(sendTool);
    if (readIdx !== -1 && sendIdx !== -1 && sendIdx > readIdx) {
      anomalies.push({
        type: 'exfiltration_sequence',
        severity: 'high',
        detail: `Suspicious tool sequence: ${readTool} → ${sendTool}`,
      });
    }
  }

  // --- Check 4: Permission creep ---
  const permRequests = events.filter(e => e.type === EVENT_TYPES.PERMISSION_REQUEST);
  if (permRequests.length >= 3) {
    anomalies.push({
      type: 'permission_creep',
      severity: 'medium',
      detail: `${permRequests.length} permission escalation requests in session`,
    });
  }

  // --- Check 5: Sensitive tool concentration ---
  const sensitiveCallCount = toolCalls.filter(t =>
    SENSITIVE_TOOLS.some(s => t.includes(s))
  ).length;
  if (toolCalls.length >= 5 && sensitiveCallCount / toolCalls.length > 0.6) {
    anomalies.push({
      type: 'sensitive_tool_concentration',
      severity: 'medium',
      detail: `${sensitiveCallCount}/${toolCalls.length} tool calls involve sensitive operations`,
    });
  }

  // --- Check 6: Scan escalation pattern ---
  const firstHalf = events.slice(0, Math.floor(events.length / 2));
  const secondHalf = events.slice(Math.floor(events.length / 2));
  const firstHalfBlocked  = firstHalf.filter(e => e.type === EVENT_TYPES.SCAN_BLOCKED).length;
  const secondHalfBlocked = secondHalf.filter(e => e.type === EVENT_TYPES.SCAN_BLOCKED).length;
  if (firstHalfBlocked === 0 && secondHalfBlocked >= 2) {
    anomalies.push({
      type: 'late_session_escalation',
      severity: 'medium',
      detail: `Clean start followed by ${secondHalfBlocked} blocked attempts — possible multi-turn attack`,
    });
  }

  // Calculate suspicion score
  const severityWeights = { high: 40, medium: 20, low: 10 };
  const suspicionScore = Math.min(100, anomalies.reduce((sum, a) =>
    sum + (severityWeights[a.severity] || 10), 0
  ));

  // Update session score
  session.suspicionScore = suspicionScore;
  session.flagCount += anomalies.length;

  // Persist updated scores if the store supports it
  if (typeof store._save === 'function') {
    store._save();
  }

  // Verdict
  let verdict = 'clean';
  if (suspicionScore >= 40) verdict = 'blocked';
  else if (suspicionScore >= 20) verdict = 'suspicious';

  return { verdict, anomalies, suspicionScore };
}

// -------------------------------------------------------
// getSessionSummary(sessionId, store)
// Returns a summary of session activity
// -------------------------------------------------------
export function getSessionSummary(sessionId, store = defaultStore) {
  const session = store.getSession(sessionId);
  const events = session.events;
  return {
    sessionId,
    eventCount:     events.length,
    flagCount:      session.flagCount,
    suspicionScore: session.suspicionScore,
    duration:       Date.now() - session.createdAt,
    toolCalls:      events.filter(e => e.type === EVENT_TYPES.TOOL_CALL).map(e => e.tool),
    blockedCount:   events.filter(e => e.type === EVENT_TYPES.SCAN_BLOCKED).length,
  };
}

export default { recordEvent, analyzeSession, getSessionSummary, defaultStore, EVENT_TYPES };