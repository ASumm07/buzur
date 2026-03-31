import re

content = open('/home/albert/buzur/src/index.js').read()

base64_block = """
// -- Base64 Decoder
// Detects base64 encoded strings and scans decoded content for injection patterns
// Attackers encode injections to bypass pattern matching

function decodeBase64Segments(text) {
  if (!text) return text;
  const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g;
  return text.replace(base64Pattern, (match) => {
    try {
      const decoded = Buffer.from(match, 'base64').toString('utf8');
      // Only replace if decoded text is printable and different from original
      if (/^[\\x20-\\x7E]+$/.test(decoded) && decoded !== match) {
        return decoded;
      }
      return match;
    } catch {
      return match;
    }
  });
}
"""

content = content.replace(
  'export function scan(text) {\n  if (!text) return { clean: text, blocked: 0, triggered: [] };\n  let s = normalizeHomoglyphs(text);',
  base64_block + '\nexport function scan(text) {\n  if (!text) return { clean: text, blocked: 0, triggered: [] };\n  let s = normalizeHomoglyphs(text);\n  s = decodeBase64Segments(s);'
)

content = content.replace(
  'export default { scan, getTrustTier, isTier1Domain, addTrustedDomain, normalizeHomoglyphs };',
  'export default { scan, getTrustTier, isTier1Domain, addTrustedDomain, normalizeHomoglyphs, decodeBase64Segments };'
)

open('/home/albert/buzur/src/index.js', 'w').write(content)
print("Done.")
