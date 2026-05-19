import { describe, it, expect } from "vitest";
import { scan, redact, luhnValid, ibanValid } from "../src/index.js";

describe("scan: emails", () => {
  it("detects standard emails", () => {
    const r = scan("Contact me at alice@example.com or bob.smith+work@sub.domain.co.uk");
    expect(r.findings.filter((f) => f.category === "email")).toHaveLength(2);
  });
});

describe("scan: SSN", () => {
  it("detects valid SSN", () => {
    expect(scan("SSN: 123-45-6789").found).toBe(true);
  });
  it("rejects 000/666/9xx area numbers", () => {
    expect(scan("000-12-3456 or 666-12-3456 or 900-12-3456").findings).toHaveLength(0);
  });
});

describe("scan: credit card with Luhn validation", () => {
  it("accepts a valid Visa", () => {
    // 4111 1111 1111 1111 is a well-known Luhn-valid test number
    expect(scan("CC: 4111 1111 1111 1111").findings.some((f) => f.category === "credit-card")).toBe(true);
  });

  it("rejects same-shape number with bad checksum", () => {
    expect(scan("CC: 4111 1111 1111 1112").findings.some((f) => f.category === "credit-card")).toBe(false);
  });

  it("accepts an Amex with dashes", () => {
    // 3782 822463 10005 → Luhn-valid Amex
    expect(scan("3782-822463-10005").findings.some((f) => f.category === "credit-card")).toBe(true);
  });
});

describe("scan: phones", () => {
  it("US format", () => {
    expect(scan("(415) 555-1234").findings.some((f) => f.category === "phone")).toBe(true);
    expect(scan("415-555-1234").findings.some((f) => f.category === "phone")).toBe(true);
  });
  it("international", () => {
    expect(scan("+40 723 456 789").findings.some((f) => f.category === "phone")).toBe(true);
  });
});

describe("scan: IBAN", () => {
  it("accepts a valid IBAN", () => {
    // GB82 WEST 1234 5698 7654 32 — standard test IBAN
    expect(scan("Pay to: GB82 WEST 1234 5698 7654 32").findings.some((f) => f.category === "iban")).toBe(true);
  });
  it("rejects same-shape with bad checksum", () => {
    expect(scan("Pay to: GB99 WEST 1234 5698 7654 32").findings.some((f) => f.category === "iban")).toBe(false);
  });
});

describe("scan: IPs", () => {
  it("IPv4", () => {
    expect(scan("Server at 192.168.1.10").findings.some((f) => f.category === "ipv4")).toBe(true);
  });
  it("IPv6", () => {
    expect(scan("Server at 2001:db8::1").findings.some((f) => f.category === "ipv6")).toBe(true);
  });
});

describe("scan: Bitcoin", () => {
  it("P2PKH", () => {
    expect(scan("Send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").findings.some((f) => f.category === "bitcoin-address")).toBe(true);
  });
  it("Bech32", () => {
    expect(scan("Send to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq").findings.some((f) => f.category === "bitcoin-address")).toBe(true);
  });
});

describe("scan: filters", () => {
  it("include filter", () => {
    const r = scan("a@b.com and 123-45-6789", { include: ["email"] });
    expect(r.findings.every((f) => f.category === "email")).toBe(true);
  });
  it("exclude filter", () => {
    const r = scan("a@b.com and 123-45-6789", { exclude: ["email"] });
    expect(r.findings.every((f) => f.category !== "email")).toBe(true);
  });
});

describe("scan: overlap deduplication", () => {
  it("does not double-report when patterns overlap", () => {
    // The same number could match both phone and SSN-shaped patterns
    const r = scan("Call 415-555-1234.");
    const phones = r.findings.filter((f) => f.category === "phone");
    expect(phones).toHaveLength(1);
  });
});

describe("redact", () => {
  it("replaces with [PII:<category>]", () => {
    const out = redact("email: a@b.com");
    expect(out).toBe("email: [PII:email]");
  });
  it("custom replacement function", () => {
    const out = redact("a@b.com", { replacement: (f) => `<${f.label}>` });
    expect(out).toBe("<email address>");
  });
  it("returns text unchanged when nothing matches", () => {
    expect(redact("just some text")).toBe("just some text");
  });
});

describe("ignoreCodeFences", () => {
  it("skips matches in ``` ... ``` blocks", () => {
    const text = "before\n```\nemail: a@b.com\n```\nafter";
    expect(scan(text).found).toBe(true);
    expect(scan(text, { ignoreCodeFences: true }).found).toBe(false);
  });
});

describe("luhnValid", () => {
  it.each([
    ["4111111111111111", true],
    ["4111111111111112", false],
    ["378282246310005", true],
    ["6011111111111117", true],
    ["1234567890", false],
  ])("%s → %s", (num, expected) => {
    expect(luhnValid(num)).toBe(expected);
  });
});

describe("ibanValid", () => {
  it.each([
    ["GB82 WEST 1234 5698 7654 32", true],
    ["DE89370400440532013000", true],
    ["GB99 WEST 1234 5698 7654 32", false],
    ["not an iban", false],
  ])("%s → %s", (iban, expected) => {
    expect(ibanValid(iban)).toBe(expected);
  });
});
