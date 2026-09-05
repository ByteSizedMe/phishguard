import { legitimateDomains } from "../data/legitimate-domains";
import { parse } from "tldts";
import { domainToUnicode } from "node:url";

export interface TyposquattingResult {
  isTyposquatting: boolean;
  matchedDomain: string | null;
  matchedBrand: string | null;
  distance: number | null;
  similarity: number | null;
  mutations: TyposquattingMutation[];
}

export type TyposquattingMutation =
  | "insertion"
  | "deletion"
  | "substitution"
  | "transposition"
  | "prefix"
  | "suffix"
  | "tld-variation"
  | "homoglyph"
  | "idn"
  | "unknown";

export type TldMutation = "tld-variation";

const suspiciousPrefixSuffixTerms = [
  "login",
  "signin",
  "sign-in",
  "secure",
  "security",
  "account",
  "accounts",
  "verify",
  "verification",
  "update",
  "support",
  "help",
  "auth",
  "authenticate",
  "billing",
  "payment",
  "payments",
];

const suspiciousTlds = [
  "tk",
  "ml",
  "ga",
  "cf",
  "gq",
  "xyz",
  "top",
  "click",
  "work",
  "link",
  "online",
  "site",
  "live",
  "zip",
  "mov",
];

const homoglyphMap: Record<string, string> = {
  // Cyrillic
  а: "a",
  е: "e",
  і: "i",
  о: "o",
  р: "p",
  с: "c",
  х: "x",
  у: "y",
  ӏ: "l",

  // Greek uppercase
  Α: "a",
  Β: "b",
  Ε: "e",
  Ι: "i",
  Ο: "o",
  Ρ: "p",
  Τ: "t",
  Χ: "x",

  // Greek lowercase
  α: "a",
  β: "b",
  ε: "e",
  ι: "i",
  ο: "o",
  ρ: "p",
  τ: "t",
  χ: "x",

  // Other visually similar characters
  ɑ: "a",
  "℮": "e",
  ℓ: "l",
  ⅼ: "l",
  ᴏ: "o",
  ᴜ: "u",
};

export function normalizeIdnHostname(hostname: string): {
  unicodeHostname: string;
  hasPunycode: boolean;
} {
  const normalizedHostname = hostname.toLowerCase();

  const hasPunycode = normalizedHostname
    .split(".")
    .some((label) => label.startsWith("xn--"));

  const unicodeHostname = domainToUnicode(normalizedHostname);

  return {
    unicodeHostname,
    hasPunycode,
  };
}

export function damerauLevenshteinDistance(a: string, b: string): number {
  const rows = a.length + 1;
  const columns = b.length + 1;

  const matrix: number[][] = Array.from({ length: rows }, () =>
    Array(columns).fill(0),
  );

  // Empty string -> string
  for (let i = 0; i < rows; i++) {
    matrix[i][0] = i;
  }

  // String -> empty string
  for (let j = 0; j < columns; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i < rows; i++) {
    for (let j = 1; j < columns; j++) {
      const substitutionCost = a[i - 1] === b[j - 1] ? 0 : 1;

      // Insertion
      const insertion = matrix[i][j - 1] + 1;

      // Deletion
      const deletion = matrix[i - 1][j] + 1;

      // Substitution
      const substitution = matrix[i - 1][j - 1] + substitutionCost;

      matrix[i][j] = Math.min(insertion, deletion, substitution);

      // Adjacent transposition
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        matrix[i][j] = Math.min(matrix[i][j], matrix[i - 2][j - 2] + 1);
      }
    }
  }

  return matrix[a.length][b.length];
}

export function calculateSimilarity(a: string, b: string): number {
  const distance = damerauLevenshteinDistance(a, b);
  const maxLength = Math.max(a.length, b.length);

  if (maxLength === 0) {
    return 1;
  }

  return 1 - distance / maxLength;
}

export function detectMutation(
  original: string,
  candidate: string,
): TyposquattingMutation {
  if (original === candidate) {
    return "unknown";
  }

  // Transposition
  if (original.length === candidate.length) {
    let differences: number[] = [];

    for (let i = 0; i < original.length; i++) {
      if (original[i] !== candidate[i]) {
        differences.push(i);
      }
    }

    if (
      differences.length === 2 &&
      differences[1] === differences[0] + 1 &&
      original[differences[0]] === candidate[differences[1]] &&
      original[differences[1]] === candidate[differences[0]]
    ) {
      return "transposition";
    }
  }

  // Insertion
  if (candidate.length === original.length + 1) {
    for (let i = 0; i < candidate.length; i++) {
      const withoutCharacter = candidate.slice(0, i) + candidate.slice(i + 1);

      if (withoutCharacter === original) {
        return "insertion";
      }
    }
  }

  // Deletion
  if (original.length === candidate.length + 1) {
    for (let i = 0; i < original.length; i++) {
      const withoutCharacter = original.slice(0, i) + original.slice(i + 1);

      if (withoutCharacter === candidate) {
        return "deletion";
      }
    }
  }

  // Substitution
  if (original.length === candidate.length) {
    let differences = 0;

    for (let i = 0; i < original.length; i++) {
      if (original[i] !== candidate[i]) {
        differences++;
      }
    }

    if (differences === 1) {
      return "substitution";
    }
  }

  return "unknown";
}

export function detectPrefixSuffix(
  legitimateLabel: string,
  candidateLabel: string,
): "prefix" | "suffix" | null {
  const normalizedLegitimate = legitimateLabel.toLowerCase();
  const normalizedCandidate = candidateLabel.toLowerCase();

  if (normalizedCandidate.startsWith(normalizedLegitimate)) {
    const suffix = normalizedCandidate
      .slice(normalizedLegitimate.length)
      .replace(/^-+/, "");

    if (suspiciousPrefixSuffixTerms.includes(suffix)) {
      return "suffix";
    }
  }

  if (normalizedCandidate.endsWith(normalizedLegitimate)) {
    const prefix = normalizedCandidate
      .slice(0, normalizedCandidate.length - normalizedLegitimate.length)
      .replace(/-+$/, "");

    if (suspiciousPrefixSuffixTerms.includes(prefix)) {
      return "prefix";
    }
  }

  return null;
}

export function detectTldManipulation(
  legitimateDomain: string,
  candidateHostname: string,
): TldMutation | null {
  const parsedLegitimate = parse(legitimateDomain);
  const parsedCandidate = parse(candidateHostname);

  if (!parsedLegitimate.publicSuffix || !parsedCandidate.publicSuffix) {
    return null;
  }

  if (parsedCandidate.publicSuffix === parsedLegitimate.publicSuffix) {
    return null;
  }

  if (suspiciousTlds.includes(parsedCandidate.publicSuffix)) {
    return "tld-variation";
  }

  return null;
}

export function detectHomoglyph(
  legitimateLabel: string,
  candidateLabel: string,
): boolean {
  if (legitimateLabel === candidateLabel) {
    return false;
  }

  const normalizedCandidate = normalizeHomoglyphs(candidateLabel);

  // Homoglyph detection only applies when the candidate
  // actually contains a character that was normalized.
  if (normalizedCandidate === candidateLabel) {
    return false;
  }

  if (normalizedCandidate === legitimateLabel) {
    return true;
  }

  const distance = damerauLevenshteinDistance(
    normalizedCandidate,
    legitimateLabel,
  );

  const similarity = calculateSimilarity(normalizedCandidate, legitimateLabel);

  return distance <= 2 && similarity >= 0.7;
}

export function normalizeHomoglyphs(value: string): string {
  return [...value]
    .map((character) => homoglyphMap[character] ?? character)
    .join("");
}

export function normalizeDigitSubstitutions(value: string): string {
  const digitMap: Record<string, string> = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
  };

  return [...value]
    .map((character) => digitMap[character] ?? character)
    .join("");
}

export function detectDigitSubstitution(
  original: string,
  candidate: string,
): boolean {
  const digitMap: Record<string, string> = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
  };

  if (original.length !== candidate.length) {
    return false;
  }

  let differences = 0;

  for (let i = 0; i < original.length; i++) {
    if (original[i] === candidate[i]) {
      continue;
    }

    const normalizedCandidate = digitMap[candidate[i]] ?? candidate[i];

    if (normalizedCandidate !== original[i]) {
      return false;
    }

    differences++;
  }

  return differences > 0;
}

export function checkTyposquatting(hostname: string): TyposquattingResult {
  const normalizedHostname = hostname.toLowerCase();

  const { unicodeHostname, hasPunycode } =
    normalizeIdnHostname(normalizedHostname);

  const parsedHostname = parse(normalizedHostname);

  if (!parsedHostname.domain) {
    return {
      isTyposquatting: false,
      matchedDomain: null,
      matchedBrand: null,
      distance: null,
      similarity: null,
      mutations: [],
    };
  }

  const registrableDomain = parsedHostname.domain;

  const parsedUnicodeHostname = parse(unicodeHostname);

  if (!parsedUnicodeHostname.domain) {
    return {
      isTyposquatting: false,
      matchedDomain: null,
      matchedBrand: null,
      distance: null,
      similarity: null,
      mutations: [],
    };
  }

  const unicodeRegistrableDomain = parsedUnicodeHostname.domain;

  let bestMatch: {
    domain: string;
    brand: string;
    distance: number;
    similarity: number;
    mutations: TyposquattingMutation[];
  } | null = null;

  for (const legitimate of legitimateDomains) {
    const legitimateDomain = legitimate.domain.toLowerCase();

    if (registrableDomain === legitimateDomain) {
      continue;
    }

    const parsedCandidate = parse(unicodeRegistrableDomain);
    const parsedLegitimate = parse(legitimateDomain);

    if (
      !parsedCandidate.domainWithoutSuffix ||
      !parsedLegitimate.domainWithoutSuffix
    ) {
      continue;
    }

    const hostnameLabel = parsedCandidate.domainWithoutSuffix;
    const legitimateLabel = parsedLegitimate.domainWithoutSuffix;

    const normalizedCandidateLabel = normalizeDigitSubstitutions(
      normalizeHomoglyphs(hostnameLabel),
    );

    const normalizedLegitimateLabel = normalizeDigitSubstitutions(
      normalizeHomoglyphs(legitimateLabel),
    );

    const distance = damerauLevenshteinDistance(
      normalizedCandidateLabel,
      normalizedLegitimateLabel,
    );

    const similarity = calculateSimilarity(
      normalizedCandidateLabel,
      normalizedLegitimateLabel,
    );

    const mutation = detectMutation(legitimateLabel, hostnameLabel);

    const digitSubstitutionMutation = detectDigitSubstitution(
      legitimateLabel,
      hostnameLabel,
    );

    const homoglyphMutation = detectHomoglyph(legitimateLabel, hostnameLabel);

    const prefixSuffixMutation = detectPrefixSuffix(
      legitimateLabel,
      hostnameLabel,
    );

    const tldMutation =
      normalizedCandidateLabel === normalizedLegitimateLabel ||
      (distance <= 2 && similarity >= 0.7)
        ? detectTldManipulation(legitimateDomain, registrableDomain)
        : null;

    const mutations: TyposquattingMutation[] = [];

    if (mutation !== "unknown") {
      mutations.push(mutation);
    }

    if (digitSubstitutionMutation && !mutations.includes("substitution")) {
      mutations.push("substitution");
    }

    if (homoglyphMutation) {
      mutations.push("homoglyph");
    }

    if (prefixSuffixMutation !== null) {
      mutations.push(prefixSuffixMutation);
    }

    if (tldMutation !== null) {
      mutations.push(tldMutation);
    }

    const hasPlausibleMutation =
      (distance <= 1 && similarity >= 0.7) ||
      (distance === 2 && similarity >= 0.8) ||
      mutations.includes("prefix") ||
      mutations.includes("suffix") ||
      mutations.includes("tld-variation") ||
      mutations.includes("homoglyph");

    if (!hasPlausibleMutation) {
      continue;
    }

    if (bestMatch === null || similarity > bestMatch.similarity) {
      bestMatch = {
        domain: legitimate.domain,
        brand: legitimate.brand,
        distance,
        similarity,
        mutations,
      };
    }
  }

  if (bestMatch === null) {
    return {
      isTyposquatting: false,
      matchedDomain: null,
      matchedBrand: null,
      distance: null,
      similarity: null,
      mutations: [],
    };
  }

  const isTyposquatting =
    (bestMatch.distance <= 1 && bestMatch.similarity >= 0.7) ||
    (bestMatch.distance === 2 && bestMatch.similarity >= 0.8) ||
    bestMatch.mutations.includes("prefix") ||
    bestMatch.mutations.includes("suffix") ||
    bestMatch.mutations.includes("tld-variation") ||
    bestMatch.mutations.includes("homoglyph");

  if (isTyposquatting && hasPunycode && !bestMatch.mutations.includes("idn")) {
    bestMatch.mutations.push("idn");
  }

  if (!isTyposquatting) {
    return {
      isTyposquatting: false,
      matchedDomain: null,
      matchedBrand: null,
      distance: null,
      similarity: null,
      mutations: [],
    };
  }

  return {
    isTyposquatting: true,
    matchedDomain: bestMatch.domain,
    matchedBrand: bestMatch.brand,
    distance: bestMatch.distance,
    similarity: bestMatch.similarity,
    mutations: bestMatch.mutations,
  };
}
