import * as net from "node:net";
import { parse } from "tldts";

export interface UrlAnalysis {
  parsedUrl: URL;
  url: string;
  protocol: string;
  hostname: string;
  originalHostname: string;
  pathname: string;
  port: string;
  search: string;
  hash: string;
  urlLength: number;
  subdomainCount: number;
  isIpAddress: boolean;
  hasAtSymbol: boolean;
  hostnameLength: number;
  pathnameLength: number;
  digitCount: number;
  isHttps: boolean;
  specialCharCount: number;
  hyphenCount: number;
  dotCount: number;
  encodedCharCount: number;
  queryLength: number;
  username: string;
  password: string;
  redirectParams: URLSearchParams;
  tld: string;
  domain: string | null;
  subdomain: string | null;
  hasPunyCode: boolean;
  doubleEncodedCharCount: {
    hostname: number;
    pathname: number;
    query: number;
    username: number;
    password: number;
  };
  suspiciousEncoding: SuspiciousEncoding[];
}

type EncodingLocation = "username" | "password" | "pathname" | "query";

export interface SuspiciousEncoding {
  encoding: string;
  location: EncodingLocation;
}

function extractOriginalHostname(url: string): string {
  const match = url.match(
    /^[a-zA-Z][a-zA-Z\d+.-]*:\/\/(?:[^/?#]*@)?(\[[^\]]+\]|[^/?#:]+)(?::\d+)?(?:[/?#]|$)/,
  );

  return match?.[1] ?? "";
}

export function analyzeUrl(url: string): UrlAnalysis {
  const parsedUrl = new URL(url);
  const originalHostname = extractOriginalHostname(url);

  const result: UrlAnalysis = {
    parsedUrl: parsedUrl,
    url: url,
    protocol: parsedUrl.protocol,
    hostname: parsedUrl.hostname,
    originalHostname: originalHostname,
    pathname: parsedUrl.pathname,
    port: parsedUrl.port,
    search: parsedUrl.search,
    hash: parsedUrl.hash,
    urlLength: url.length,
    subdomainCount: subdomainCount(parsedUrl),
    isIpAddress: isIP(parsedUrl),
    hasAtSymbol: url.includes("@"),
    hostnameLength: parsedUrl.hostname.length,
    pathnameLength: parsedUrl.pathname.length,
    digitCount: isIP(parsedUrl)
      ? 0
      : (parsedUrl.hostname.match(/\d/g) || []).length,
    isHttps: parsedUrl.protocol === "https:",
    specialCharCount: specialCharCount(url),
    hyphenCount: (parsedUrl.hostname.match(/-/g) || []).length,
    dotCount: (parsedUrl.hostname.match(/\./g) || []).length,
    encodedCharCount: encodedCharCount(url),
    queryLength: parsedUrl.search.length,
    username: parsedUrl.username,
    password: parsedUrl.password,
    redirectParams: parsedUrl.searchParams,
    tld: getTld(parsedUrl),
    domain: findDomain(parsedUrl.hostname),
    subdomain: findSubDomain(parsedUrl.hostname),
    hasPunyCode: parsedUrl.hostname
      .split(".")
      .some((label) => label.toLowerCase().startsWith("xn--")),
    doubleEncodedCharCount: doubleEncodedCharCount(parsedUrl),
    suspiciousEncoding: [
      ...findSuspiciousEncoded(parsedUrl.username, "username"),
      ...findSuspiciousEncoded(parsedUrl.password, "password"),
      ...findSuspiciousEncoded(parsedUrl.pathname, "pathname"),
      ...findSuspiciousEncoded(parsedUrl.search, "query"),
    ],
  };

  return result;
}

function isIP(parsedUrl: URL): boolean {
  const hostname = parsedUrl.hostname.replace(/^\[|\]$/g, "");
  return net.isIPv4(hostname) || net.isIPv6(hostname);
}

function subdomainCount(parsedUrl: URL): number {
  return parse(parsedUrl.hostname).subdomain?.split(".").length ?? 0;
}

function specialCharCount(url: string): number {
  const excludedChars = [":", "/", ".", "?", "=", "#"];

  const specialCharCount = url.split("").filter((char) => {
    const isAlphanumeric = /^[a-zA-Z0-9]$/.test(char);
    const isWhitespace = /^\s$/.test(char);
    const isExcluded = excludedChars.includes(char);

    return !isAlphanumeric && !isWhitespace && !isExcluded;
  }).length;

  return specialCharCount;
}

function encodedCharCount(url: string): number {
  const matches = url.match(/%[0-9a-fA-F]{2}/g);
  const encodedCount: number = matches ? matches.length : 0;

  return encodedCount;
}

function getTld(parsedUrl: URL): string {
  return parse(parsedUrl.hostname).publicSuffix ?? "";
}

function findDomain(hostname: string): string | null {
  const result = parse(hostname);
  return result.domain;
}

function findSubDomain(hostname: string): string | null {
  const result = parse(hostname);
  return result.subdomain;
}

function doubleEncodedCharCount(parsedUrl: URL): {
  hostname: number;
  pathname: number;
  query: number;
  username: number;
  password: number;
} {
  const pattern = /%25[0-9a-fA-F]{2}/g;

  return {
    hostname: parsedUrl.hostname.match(pattern)?.length ?? 0,
    pathname: parsedUrl.pathname.match(pattern)?.length ?? 0,
    query: parsedUrl.search.match(pattern)?.length ?? 0,
    username: parsedUrl.username.match(pattern)?.length ?? 0,
    password: parsedUrl.password.match(pattern)?.length ?? 0,
  };
}

function findSuspiciousEncoded(
  value: string,
  location: EncodingLocation,
): SuspiciousEncoding[] {
  const matches = value.match(/%[0-9a-fA-F]{2}/g) ?? [];

  const suspiciousEncoded = new Set(["%2f", "%40", "%3f", "%23"]);

  return matches
    .filter((match) => suspiciousEncoded.has(match.toLowerCase()))
    .map((match) => ({
      encoding: match,
      location: location,
    }));
}
