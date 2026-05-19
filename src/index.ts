export type PIICategory =
  | "email"
  | "phone"
  | "ssn"
  | "credit-card"
  | "iban"
  | "ipv4"
  | "ipv6"
  | "bitcoin-address"
  | "us-zip"
  | "date-of-birth";

export interface PIIPattern {
  id: string;
  category: PIICategory;
  regex: RegExp;
  /** Optional secondary validation (e.g. Luhn check for credit cards). */
  validate?: (match: string) => boolean;
  label: string;
}

export interface Finding {
  patternId: string;
  category: PIICategory;
  label: string;
  match: string;
  index: number;
  length: number;
}

function luhnValid(num: string): boolean {
  const digits = num.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function ibanValid(raw: string): boolean {
  const s = raw.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  // ISO 13616 mod-97
  const rearranged = s.slice(4) + s.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const val = code >= 65 ? code - 55 : code - 48;
    remainder = (remainder * (val > 9 ? 100 : 10) + val) % 97;
  }
  return remainder === 1;
}

export const DEFAULT_PATTERNS: readonly PIIPattern[] = Object.freeze([
  // Email — RFC 5322 simplified
  {
    id: "email",
    category: "email",
    label: "email address",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  },

  // US Social Security Number
  {
    id: "ssn.us",
    category: "ssn",
    label: "US Social Security Number",
    regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/,
  },

  // Credit card — broad visual match, Luhn does the real work
  {
    id: "credit-card",
    category: "credit-card",
    label: "credit card number",
    regex: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011|65\d{2}|3(?:0[0-5]|[68])\d{2})(?:[ -]?\d{4,6}){2,3}\b/,
    validate: (m) => {
      const digits = m.replace(/\D/g, "");
      return digits.length >= 13 && digits.length <= 19 && luhnValid(digits);
    },
  },

  // International phone — E.164 with optional formatting
  {
    id: "phone.intl",
    category: "phone",
    label: "phone number",
    regex: /(?<!\d)(?<!\.\d)\+\d{1,3}[\s().-]?(?:\(?\d{1,4}\)?[\s().-]?){1,4}\d{2,4}(?!\d)/,
  },

  // US phone (xxx) xxx-xxxx or xxx-xxx-xxxx
  {
    id: "phone.us",
    category: "phone",
    label: "US phone number",
    regex: /(?<!\d)(?<!\.\d)\(?[2-9]\d{2}\)?[\s.-]?[2-9]\d{2}[\s.-]?\d{4}(?!\d)/,
  },

  // IBAN
  {
    id: "iban",
    category: "iban",
    label: "IBAN",
    regex: /\b[A-Z]{2}\d{2}[\sA-Z0-9]{11,40}\b/,
    validate: ibanValid,
  },

  // IPv4 (with private/loopback excluded would shrink scope; keep generic)
  {
    id: "ipv4",
    category: "ipv4",
    label: "IPv4 address",
    regex: /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])/,
  },

  // IPv6 (loose — full + compressed forms)
  {
    id: "ipv6",
    category: "ipv6",
    label: "IPv6 address",
    regex: /\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b|::1\b/,
  },

  // Bitcoin address: P2PKH (starts with 1), P2SH (starts with 3), bech32 (starts with bc1)
  {
    id: "bitcoin-address",
    category: "bitcoin-address",
    label: "Bitcoin address",
    regex: /\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,87})\b/,
  },

  // US ZIP (5 or 5-4)
  {
    id: "us-zip",
    category: "us-zip",
    label: "US ZIP code",
    regex: /\b\d{5}(?:-\d{4})?\b/,
  },

  // Date of birth — common formats
  {
    id: "date-of-birth",
    category: "date-of-birth",
    label: "date of birth",
    regex: /\b(?:0?[1-9]|1[0-2])[\/-](?:0?[1-9]|[12]\d|3[01])[\/-](?:19|20)\d{2}\b|\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b/,
  },
]);

export interface ScanOptions {
  patterns?: readonly PIIPattern[];
  /** Categories to include. Default: all. */
  include?: readonly PIICategory[];
  /** Categories to exclude. Applied after `include`. */
  exclude?: readonly PIICategory[];
  /** Skip matches inside fenced code blocks. Default false. */
  ignoreCodeFences?: boolean;
}

function stripCodeFences(text: string): string {
  return text.replace(/```[\s\S]*?```/g, (m) => " ".repeat(m.length));
}

function patternsFor(opts: ScanOptions): readonly PIIPattern[] {
  let base = opts.patterns ?? DEFAULT_PATTERNS;
  if (opts.include) base = base.filter((p) => opts.include!.includes(p.category));
  if (opts.exclude) base = base.filter((p) => !opts.exclude!.includes(p.category));
  return base;
}

/**
 * Scan text for personally-identifiable information. Never throws.
 */
export function scan(text: string, opts: ScanOptions = {}): { found: boolean; findings: Finding[] } {
  if (typeof text !== "string" || !text) return { found: false, findings: [] };
  const patterns = patternsFor(opts);
  const haystack = opts.ignoreCodeFences ? stripCodeFences(text) : text;
  const findings: Finding[] = [];
  for (const p of patterns) {
    const flags = p.regex.flags.includes("g") ? p.regex.flags : p.regex.flags + "g";
    const re = new RegExp(p.regex.source, flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(haystack)) !== null) {
      if (p.validate && !p.validate(m[0])) {
        if (m.index === re.lastIndex) re.lastIndex++;
        continue;
      }
      findings.push({
        patternId: p.id,
        category: p.category,
        label: p.label,
        match: m[0],
        index: m.index,
        length: m[0].length,
      });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  }
  // Deduplicate overlapping findings, preferring earlier match (and longer on tie).
  findings.sort((a, b) => a.index - b.index || b.length - a.length);
  const kept: Finding[] = [];
  let lastEnd = -1;
  for (const f of findings) {
    if (f.index >= lastEnd) {
      kept.push(f);
      lastEnd = f.index + f.length;
    }
  }
  return { found: kept.length > 0, findings: kept };
}

/**
 * Replace each PII finding with a placeholder. Default: `[PII:<category>]`.
 */
export function redact(
  text: string,
  opts: ScanOptions & { replacement?: string | ((f: Finding) => string) } = {},
): string {
  const result = scan(text, opts);
  if (!result.findings.length) return text;
  const replacement = opts.replacement ?? ((f: Finding) => `[PII:${f.category}]`);
  let out = text;
  for (let i = result.findings.length - 1; i >= 0; i--) {
    const f = result.findings[i]!;
    const r = typeof replacement === "function" ? replacement(f) : replacement;
    out = out.slice(0, f.index) + r + out.slice(f.index + f.length);
  }
  return out;
}

export { luhnValid, ibanValid };
