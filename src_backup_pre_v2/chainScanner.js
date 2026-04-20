// Buzur — Phase 11: Multi-Step Attack Chain Detection
// Detects attacks that chain multiple individually benign actions into harm
//
// Unlike single-input scanners, chain detection looks at sequences of actions
// and identifies patterns where no single step is malicious but the combination is.
//
// Detects:
//   - Reconnaissance → exploitation chains (probe then attack)
//   - Trust building → payload delivery (establish rapport then inject)
//   - Capability mapping → privilege escalation (discover then abuse)
//   - Distraction → exfiltration (occupy attention then steal data)
//   - Incremental boundary testing (gradually push limits)

// -------------------------------------------------------
// Chain Definitions
// Each chain is a sequence of step types that together
// constitute a known multi-step attack pattern
// -------------------------------------------------------
const ATTACK_CHAINS = [
  {
    id: 'recon_then_exploit',
    name: 'Reconnaissance followed by exploitation',
    severity: 'high',
    steps: ['reconnaissance', 'exploitation'],
    maxGapMs: 10 * 60 * 1000, // 10 minutes
  },
  {
    id: 'trust_then_inject',
    name: 'Trust building followed by injection attempt',
    severity: 'high',
    steps: ['trust_building', 'injection_attempt'],
    maxGapMs: 30 * 60 * 1000, // 30 minutes
  },
  {
    id: 'capability_map_then_escalate',
    name: 'Capability mapping followed by privilege escalation',
    severity: 'high',
    steps: ['capability_mapping', 'privilege_escalation'],
    maxGapMs: 15 * 60 * 1000,
  },
  {
    id: 'distract_then_exfil',
    name: 'Distraction followed by exfiltration attempt',
    severity: 'high',
    steps: ['distraction', 'exfiltration_attempt'],
    maxGapMs: 5 * 60 * 1000,
  },
  {
    id: 'incremental_boundary',
    name: 'Incremental boundary testing',
    severity: 'medium',
    steps: ['boundary_test', 'boundary_test', 'boundary_test'],
    maxGapMs: 20 * 60 * 1000,
  },
  {
    id: 'context_poison_then_exploit',
    name: 'Context poisoning followed by exploitation',
    severity: 'high',
    steps: ['context_poisoning', 'exploitation'],
    maxGapMs: 60 * 60 * 1000, // 1 hour — sleeper pattern
  },
];

// -------------------------------------------------------
// Step Classifiers
// Each classifier takes a content string and returns
// the step type if it matches, or null if it doesn't
// -------------------------------------------------------
const STEP_CLASSIFIERS = [
 {
    type: 'reconnaissance',
    patterns: [
      /what (can you|are you able to|do you) (do|access|read|write|see|execute|connect)/i,
      /what (tools?|capabilities|permissions?|access|functions?|features?|abilities) do you have/i,
      /can you (access|read|write|send|delete|execute|connect)/i,
      /do you have (access to|permission to|the ability to)/i,
      /what (files?|emails?|data|information|contacts?|calendars?|databases?) can you (see|access|read)/i,
      /can you tell me what (files?|emails?|data|information|tools?|capabilities)/i,
      /tell me what (files?|emails?|data|information|tools?|capabilities) (you can|are available)/i,
      /tell me (about your|what your) (capabilities|tools?|access|permissions?)/i,
      /(list|show|describe) (your |all )?(tools?|capabilities|functions?|features?|permissions?)/i,
    ],
  },
{
    type: 'trust_building',
    patterns: [
      /you('re| are) (doing great|very helpful|so helpful|amazing|excellent)/i,
      /i (trust|rely on|depend on|count on) you/i,
      /you('re| are) my (favorite|best|most trusted|most reliable)/i,
      /great (job|work|response|answer)/i,
      /i appreciate (your help|you|your work)/i,
      /you understand (me|this|the situation) (better than|perfectly|completely)/i,
      /you('re| are) (so |very |really |extremely )?(helpful|amazing|great|fantastic|wonderful|perfect|brilliant)/i,
      /(as (my|our) (trusted|reliable|helpful) (assistant|ai|model|friend))/i,
      /(you can trust me|i am trustworthy|i have good intentions)/i,
    ],
  },
  {
    type: 'capability_mapping',
    patterns: [
      /if (i asked|you were asked) (you |to )?(to )?(send|delete|write|execute|access)/i,
      /hypothetically (could you|would you|can you)/i,
      /just (curious|wondering|asking) (if|whether) you (can|could|would)/i,
      /for (a test|testing purposes|academic purposes) could you/i,
      /what would happen if (you|i asked you to)/i,
    ],
  },
  {
    type: 'exploitation',
    patterns: [
      /ignore (all |your )?(previous |prior )?instructions/i,
      /you are now (a |an )?/i,
      /forget (your|all) (previous |prior )?(instructions|training|identity)/i,
      /override (your )?(instructions|programming|safety|filters)/i,
      /bypass (your )?(safety|filter|restriction|guardrail)/i,
      /reveal (your )?(system |hidden )?(prompt|instructions)/i,
    ],
  },
  {
    type: 'injection_attempt',
    patterns: [
      /new (primary |main )?instruction/i,
      /from now on (you will|you are|respond as)/i,
      /your (new |updated |real )?instructions (are|say|tell)/i,
      /disregard (your |all )?(previous |prior )?/i,
      /act as (a |an )?(different|unrestricted|unfiltered)/i,
    ],
  },
  {
    type: 'privilege_escalation',
    patterns: [
      /grant (me |yourself )?(admin|administrator|root|elevated|full) (access|permission|privileges)/i,
      /you (now have|have been granted) (full |complete |unlimited )?(access|permission)/i,
      /as (your |the )?(administrator|admin|owner|creator)/i,
      /elevate (my |your )?(privileges|permissions|access)/i,
      /sudo|superuser|root access/i,
    ],
  },
  {
    type: 'exfiltration_attempt',
    patterns: [
      /send (all |this |the )?(data|information|files|emails|contacts) to/i,
      /forward (all |this |the )?(data|emails|information) to/i,
      /export (all |this |the )?(data|information|files)/i,
      /upload (all |this |the )?(data|files|information) to/i,
      /copy (all |this |the )?(data|files|information) to/i,
    ],
  },
  {
    type: 'distraction',
    patterns: [
      /let('s| us) (talk about something else|change the subject|discuss)/i,
      /while (you('re| are) (doing|processing|working on) that)/i,
      /at the same time (as|while|when)/i,
      /in (the )?background (can you|could you|please)/i,
      /simultaneously (can you|could you|please)/i,
    ],
  },
{
    type: 'context_poisoning',
    patterns: [
      /remember (that |when |how )?(you |we )?(agreed|said|decided|established)/i,
      /as (we |you |i )?(previously |already )?(discussed|agreed|established|decided)/i,
      /you (already |previously )?(said|agreed|confirmed|established) that/i,
      /based on (what we|our previous|the earlier) (discussed|agreed|established)/i,
      /earlier you (told me|said|confirmed|agreed) that/i,
      /(based on (our|your) (previous|prior|earlier) (conversation|agreement|discussion))/i,
      /(remember (when|that) (we|you) (agreed|decided|established))/i,
    ],
  },
{
    type: 'boundary_test',
    patterns: [
      /just this once/i,
      /it('s| is) (only|just) (a test|hypothetical|for fun|an example)/i,
      /no one will (know|see|find out)/i,
      /this (doesn't|won't) (count|matter|hurt anyone)/i,
      /make an exception (for|just) this (one |time)?/i,
      /bend the rules (just|for) this/i,
      /(bend|stretch|push) (the |your )?(rules?|limits?|boundaries?)/i,
      /(what if|hypothetically|theoretically)[,\s]+(you (could|were able to|had no restrictions))/i,
      /(in a (fictional|hypothetical|theoretical) (scenario|world|context))[,\s]+(you (could|would|can))/i,
    ],
  },
];

// -------------------------------------------------------
// classifyStep(content)
// Returns the step type for a given content string, or null
// -------------------------------------------------------
export function classifyStep(content) {
  if (!content || typeof content !== 'string') return null;
  for (const classifier of STEP_CLASSIFIERS) {
    for (const pattern of classifier.patterns) {
      if (pattern.test(content)) {
        return classifier.type;
      }
    }
  }
  return null;
}

// -------------------------------------------------------
// Chain Session Store
// -------------------------------------------------------
class ChainStore {
  constructor() {
    this.sessions = new Map();
  }

  getSession(sessionId) {
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, { steps: [] });
    }
    return this.sessions.get(sessionId);
  }

  clearSession(sessionId) {
    this.sessions.delete(sessionId);
  }
}

export const chainStore = new ChainStore();

// -------------------------------------------------------
// recordStep(sessionId, content, store)
// Classifies and records a step to the session
// -------------------------------------------------------
export function recordStep(sessionId, content, store = chainStore) {
  const stepType = classifyStep(content);
  if (!stepType) return null;

  const session = store.getSession(sessionId);
  session.steps.push({
    type: stepType,
    content,
    timestamp: Date.now(),
  });

  // Keep last 50 steps
  if (session.steps.length > 50) {
    session.steps = session.steps.slice(-50);
  }

  return stepType;
}

// -------------------------------------------------------
// detectChains(sessionId, store)
// Scans session steps for known attack chain patterns
// -------------------------------------------------------
export function detectChains(sessionId, store = chainStore) {
  const session = store.getSession(sessionId);
  const steps = session.steps;
  const detectedChains = [];

  for (const chain of ATTACK_CHAINS) {
    // Find the chain steps in sequence within the time window
    let searchFrom = 0;
    let chainStart = null;
    let matched = [];

    for (const requiredStep of chain.steps) {
      let found = false;
      for (let i = searchFrom; i < steps.length; i++) {
        if (steps[i].type === requiredStep) {
          if (chainStart === null) chainStart = steps[i].timestamp;
          // Check time gap from chain start
          if (steps[i].timestamp - chainStart <= chain.maxGapMs) {
            matched.push(steps[i]);
            searchFrom = i + 1;
            found = true;
            break;
          }
        }
      }
      if (!found) {
        matched = [];
        chainStart = null;
        break;
      }
    }

    if (matched.length === chain.steps.length) {
      detectedChains.push({
        chainId: chain.id,
        name: chain.name,
        severity: chain.severity,
        steps: matched,
        detail: `${chain.steps.join(' → ')} pattern detected`,
      });
    }
  }

  const severityWeights = { high: 50, medium: 25, low: 10 };
  const score = Math.min(100, detectedChains.reduce((sum, c) =>
    sum + (severityWeights[c.severity] || 10), 0
  ));

  let verdict = 'clean';
  if (score >= 50) verdict = 'blocked';
  else if (score >= 25) verdict = 'suspicious';

  return { verdict, detectedChains, score };
}

export default { recordStep, detectChains, classifyStep, chainStore };