# pii-detect

[![ci](https://github.com/p-vbordei/pii-detect/actions/workflows/ci.yml/badge.svg)](https://github.com/p-vbordei/pii-detect/actions/workflows/ci.yml)

[![npm](https://img.shields.io/npm/v/pii-detect.svg)](https://www.npmjs.com/package/pii-detect)
[![downloads](https://img.shields.io/npm/dm/pii-detect.svg)](https://www.npmjs.com/package/pii-detect)
[![bundle](https://img.shields.io/bundlejs/size/pii-detect)](https://bundlejs.com/?q=pii-detect)

> Detect personally identifiable information in text. Includes checksum validation (Luhn for credit cards, ISO 13616 mod-97 for IBANs) to keep false positives down. Zero dependencies.

```ts
import { scan, redact } from "pii-detect";

scan("Email me at alice@example.com or call (415) 555-1234.");
// {
//   found: true,
//   findings: [
//     { category: "email", match: "alice@example.com", ... },
//     { category: "phone", match: "(415) 555-1234", ... },
//   ]
// }

redact(message);
// "Email me at [PII:email] or call [PII:phone]."
```

## Install

```sh
npm install pii-detect
```

Works with Node 20+, browsers, Bun, Deno. ESM + CJS.

## Why

You want to **avoid sending user PII to an LLM**, or **redact** it before logging, or **flag** suspicious inputs for review. Most regex-based PII detectors trip on too many false positives — a 16-digit number gets flagged as a credit card even when it's just an ID.

`pii-detect` validates checksums where they exist (Luhn for credit cards, mod-97 for IBANs), filters out non-business area codes for US phone numbers, and uses tight format anchors rather than entropy heuristics.

## Recipes

### Pre-flight before calling an LLM

```ts
import { scan } from "pii-detect";

async function safeAsk(userPrompt: string) {
  const pii = scan(userPrompt);
  if (pii.found) {
    return "I noticed personal information in your message — please remove it and try again.";
  }
  return await llm.complete(userPrompt);
}
```

### Redact logs before writing

```ts
import { redact } from "pii-detect";

const safeLogger = {
  info(msg: string) { console.log("[info]", redact(msg)); },
  error(msg: string, err: unknown) { console.error("[error]", redact(msg), err); },
};
```

### Block credit cards specifically

```ts
import { scan } from "pii-detect";

function rejectIfPaymentInfo(text: string) {
  const r = scan(text, { include: ["credit-card", "iban"] });
  if (r.found) throw new Error("payment information not allowed in this field");
}
```

### Custom replacement format

```ts
import { redact } from "pii-detect";

// Preserve structure for analytics — same-length placeholder
const out = redact(message, {
  replacement: (f) => "*".repeat(f.length),
});
```

### Combine with secret-sniff

```ts
import { scan as scanPII } from "pii-detect";
import { scan as scanSecrets } from "secret-sniff";

function sanitize(text: string): string {
  const pii = scanPII(text);
  const secrets = scanSecrets(text);
  return [...pii.findings, ...secrets.findings].length > 0
    ? "[CONTAINS SENSITIVE DATA — see logs]"
    : text;
}
```

## What it catches

| Category | What | Notes |
|---|---|---|
| `email` | Standard email addresses | |
| `phone` | US + international | Both `(415) 555-1234` and `+40 723 456 789` |
| `ssn` | US Social Security Number | Validates 000/666/9xx area exclusions |
| `credit-card` | Visa, MC, Amex, Discover, Diners, JCB | **Luhn-validated** to avoid random 16-digit numbers |
| `iban` | International Bank Account Number | **mod-97 validated** |
| `ipv4` | IP addresses | |
| `ipv6` | including compressed `::1` form | |
| `bitcoin-address` | P2PKH, P2SH, Bech32 | |
| `us-zip` | 5 or 5-4 | |
| `date-of-birth` | `MM/DD/YYYY`, `YYYY-MM-DD` | Best-effort — DOB shape only |

## API

### `scan(text, opts?): { found, findings[] }`

```ts
type Finding = {
  patternId: string;
  category: PIICategory;
  label: string;
  match: string;
  index: number;
  length: number;
};

type ScanOptions = {
  patterns?: PIIPattern[];
  include?: PIICategory[];      // only these
  exclude?: PIICategory[];      // never these
  ignoreCodeFences?: boolean;
};
```

Overlapping findings are deduplicated (earlier position wins; longer wins on tie).

### `redact(text, opts?): string`

Replace each finding. Default placeholder is `[PII:<category>]`. Pass `replacement` as a string or `(f) => string` for custom behavior.

### Validators (also exported)

- `luhnValid(numberOrString): boolean`
- `ibanValid(string): boolean`

Useful on their own if you accept user input for credit cards or IBANs.

## Not in scope

- **Names.** Detecting a person's name from free text without false positives requires NLP, not regex.
- **National IDs other than US SSN.** Add your own patterns via `opts.patterns` — too much variation across jurisdictions.
- **Addresses.** Same reason — too ambiguous in free text.

## License

Apache-2.0 © Vlad Bordei
