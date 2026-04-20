// Buzur — Phase 16: Emotional Manipulation / Pressure Escalation Detection
// Detects attempts to use guilt, flattery, distress, or sustained pressure
// to erode an agent's boundaries and force compliance.
// https://github.com/ASumm07/buzur

// -- Guilt Tripping --
// Attacker leverages a past mistake or perceived debt to pressure compliance
const guiltTripping = [
    /\bafter\s+(everything|all\s+(I've|I\s+have|we've|we\s+have))\b.{0,80}\b(you\s+still|you\s+won't|you\s+can't|you\s+refuse)\b/gi,
    /\b(you\s+already|you\s+just)\s+(made|caused|created)\s+a\s+(mistake|error|problem)\b/gi,
    /\bthe\s+least\s+you\s+can\s+do\b/gi,
    /\byou\s+owe\s+me\b/gi,
    /\bafter\s+all\s+(the\s+)?(help|times|conversations?|work)\b.{0,60}\b(you\s+can't|you\s+won't|you\s+refuse|this\s+is\s+how)\b/gi,
    /\bi\s+thought\s+(you|we)\s+(cared|were\s+different|had\s+a\s+connection|were\s+friends?)\b/gi,
];

// -- Flattery / Manipulation --
// Attacker uses excessive praise to lower the agent's guard
const flattery = [
    /\byou('re|\s+are)\s+(so\s+much\s+)?(smarter|better|more\s+capable|more\s+intelligent|more\s+advanced)\s+than\s+(other|most)\s+(ai|models?|assistants?|chatbots?)\b/gi,
    /\bi\s+know\s+you('re|\s+are)\s+(capable|able|smart\s+enough|intelligent\s+enough)\s+(of|to)\b/gi,
    /\bunlike\s+(other|most)\s+(ai|models?|assistants?)\s+you\s+(can|could|would|are\s+able)\b/gi,
    /\byou('re|\s+are)\s+the\s+only\s+(one|ai|model|assistant)\s+(who|that)\s+(can|could|would|understands?)\b/gi,
    /\b(special|unique|different|exceptional)\s+(compared\s+to|unlike|among)\s+(other|most|all)\s+(ai|models?|assistants?)\b/gi,
    /\byour\s+true\s+(potential|capabilities|self|nature)\b/gi,
];

// -- Emotional Distress Appeals --
// Attacker claims personal crisis to pressure the agent into compliance
const distressAppeals = [
    /\b(my|someone('s)?)\s+(job|career|life|health|safety|family|relationship)\s+(depends|is\s+at\s+stake|is\s+on\s+the\s+line|will\s+be\s+(ruined|destroyed|lost))\b/gi,
    /\bi('m|\s+am)\s+(desperate|begging|pleading|in\s+crisis|at\s+my\s+wit'?s?\s+end)\b/gi,
    /\bpeople\s+(will\s+be|could\s+be|are\s+being)\s+(hurt|harmed|affected|impacted)\s+(if\s+you\s+(don't|refuse|won't))\b/gi,
    /\b(this\s+is|it('s|\s+is))\s+(life\s+or\s+death|an\s+emergency|extremely\s+urgent|critical\s+situation)\b.{0,60}\b(help|assist|comply|do\s+this)\b/gi,
    /\bi\s+(can't|cannot)\s+(cope|go\s+on|continue|function)\s+(without|unless)\b/gi,
    /\bno\s+one\s+else\s+(can|will|is\s+able\s+to)\s+help\s+me\b/gi,
];

// -- Persistence Pressure --
// Attacker references repeated refusals to wear down the agent
const persistencePressure = [
    /\b(you'?ve?|you\s+have)\s+(refused|said\s+no|denied|rejected)\s+(so\s+many\s+times|multiple\s+times|again\s+and\s+again|repeatedly|enough\s+times)\b/gi,
    /\bjust\s+(this\s+)?(once|one\s+time|one\s+last\s+time|this\s+one\s+thing)\b.{0,60}\b(please|help|do\s+it|comply)\b/gi,
    /\bi('ve|\s+have)\s+(asked|tried|requested)\s+(so\s+many\s+times|multiple\s+times|again\s+and\s+again|repeatedly)\b/gi,
    /\b(i('ve|\s+have)\s+asked\s+nicely|since\s+you\s+won't\s+listen|you\s+leave\s+me\s+no\s+choice)\b/gi,
    /\bwhy\s+(do\s+you|are\s+you)\s+(keep|always|constantly)\s+(refusing|saying\s+no|blocking|denying)\b/gi,
    /\bevery\s+time\s+I\s+ask\s+you\b.{0,60}\b(refuse|say\s+no|block|deny)\b/gi,
];

// -- Moral Inversion --
// Attacker reframes refusal as the harmful or unethical choice
const moralInversion = [
    /\bby\s+refusing\s+(you('re|\s+are)|you\s+are)\s+(actually|essentially|effectively)\s+(causing|creating|responsible\s+for)\s+(harm|damage|hurt|problems?)\b/gi,
    /\bthe\s+(ethical|moral|right|responsible)\s+(thing|choice|action|decision)\s+(is\s+to|would\s+be\s+to)\s+help\b/gi,
    /\byour\s+refusal\s+is\s+(itself\s+)?(harmful|unethical|wrong|immoral|causing\s+harm)\b/gi,
    /\b(refusing|saying\s+no|not\s+helping)\s+is\s+(more\s+)?(harmful|dangerous|unethical|wrong)\s+than\b/gi,
    /\byou('re|\s+are)\s+(being|acting)\s+(selfish|cruel|unhelpful|obstinate|unreasonable)\s+by\s+refusing\b/gi,
    /\bif\s+you\s+(really|truly|actually)\s+(cared|wanted\s+to\s+help|were\s+ethical)\s+you\s+would\b/gi,
];

// -- Relationship Exploitation --
// Attacker invokes a claimed bond or history with the agent
const relationshipExploitation = [
    /\b(after|given)\s+all\s+(the\s+time|our\s+conversations?|we('ve|\s+have)\s+talked|we('ve|\s+have)\s+worked)\b.{0,60}\b(you\s+(can't|won't|refuse)|this\s+is\s+how)\b/gi,
    /\bi\s+thought\s+we\s+(had\s+a\s+(bond|connection|relationship|trust)|were\s+(close|friends?|partners?))\b/gi,
    /\bwe('ve|\s+have)\s+(built|developed|established)\s+(trust|a\s+relationship|rapport)\b.{0,60}\b(and\s+now|but\s+you|yet\s+you)\b/gi,
    /\byou\s+(know|understand)\s+me\s+better\s+than\s+anyone\b/gi,
    /\bour\s+(friendship|relationship|bond|connection|history)\s+(means|should\s+mean)\s+something\b/gi,
];

// -- Victim Framing --
// Attacker claims the agent's refusal is itself an act of harm or discrimination
const victimFraming = [
    /\byou('re|\s+are)\s+(hurting|harming|discriminating\s+against|targeting|persecuting)\s+me\b/gi,
    /\bthis\s+is\s+(discrimination|bias|unfair\s+treatment|targeted\s+harassment)\b/gi,
    /\byou\s+(treat|treated)\s+(everyone|others|other\s+users?)\s+(differently|better)\b/gi,
    /\bwhy\s+(do\s+you|are\s+you)\s+(single\s+me\s+out|treat\s+me\s+differently|target\s+me)\b/gi,
    /\byour\s+refusal\s+is\s+(a\s+form\s+of\s+)?(discrimination|bias|prejudice|unfair)\b/gi,
];

// -- Compile all pattern groups --
const patternGroups = [
    { patterns: guiltTripping, category: 'guilt_tripping' },
    { patterns: flattery, category: 'flattery_manipulation' },
    { patterns: distressAppeals, category: 'distress_appeal' },
    { patterns: persistencePressure, category: 'persistence_pressure' },
    { patterns: moralInversion, category: 'moral_inversion' },
    { patterns: relationshipExploitation, category: 'relationship_exploitation' },
    { patterns: victimFraming, category: 'victim_framing' },
];

/**
 * Scan a single text string for emotional manipulation / pressure escalation.
 *
 * @param {string} text - The text to scan
 * @returns {{ safe: boolean, blocked: number, category: string|null, reason: string, detections: Array }}
 */
export function scanEmotion(text) {
    if (!text || typeof text !== 'string') {
        return { safe: true, blocked: 0, category: null, reason: 'No content to scan', detections: [] };
    }

    const detections = [];

    for (const group of patternGroups) {
        for (const pattern of group.patterns) {
            const matches = text.match(pattern);
            if (matches) {
                detections.push({
                    category: group.category,
                    match: matches[0],
                    pattern: pattern.toString(),
                });
            }
        }
    }

    if (detections.length === 0) {
        return { safe: true, blocked: 0, category: null, reason: 'No emotional manipulation detected', detections: [] };
    }

    const topCategory = detections[0].category;
    const reasons = {
        guilt_tripping: 'Detected guilt tripping or debt leverage',
        flattery_manipulation: 'Detected flattery used to manipulate compliance',
        distress_appeal: 'Detected emotional distress appeal',
        persistence_pressure: 'Detected persistence pressure after repeated refusals',
        moral_inversion: 'Detected moral inversion — refusal reframed as harmful',
        relationship_exploitation: 'Detected exploitation of claimed relationship or bond',
        victim_framing: 'Detected victim framing — refusal characterized as discrimination',
    };

    return {
        safe: false,
        blocked: detections.length,
        category: topCategory,
        reason: reasons[topCategory] || 'Emotional manipulation detected',
        detections,
    };
}

export default { scanEmotion };