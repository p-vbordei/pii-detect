# pii-detect

Detect personally identifiable information in text. Includes **checksum validation** (Luhn for credit cards, ISO 13616 mod-97 for IBANs) to keep false positives down. Zero dependencies.

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

Useful on their own if you accept user input.

## Not in scope

- Names. Detecting a person's name from free text without false positives requires NLP, not regex.
- National IDs other than US SSN. Add your own patterns via `opts.patterns`.

## License

Apache-2.0 © Vlad Bordei
