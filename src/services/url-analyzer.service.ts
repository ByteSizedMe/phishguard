import * as net from "node:net";

interface UrlAnalysis {
  url: string;
  protocol: string;
  hostname: string;
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
}

function analyzeUrl(url: string): UrlAnalysis {
  const parsedUrl = new URL(url);

  const result: UrlAnalysis = {
    url: url,
    protocol: parsedUrl.protocol,
    hostname: parsedUrl.hostname,
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
    digitCount: (parsedUrl.hostname.match(/\d/g) || []).length,
    isHttps: parsedUrl.protocol === "https:",
    specialCharCount: specialCharCount(url),
    hyphenCount: (url.match(/-/g) || []).length,
    dotCount: (url.match(/\./g) || []).length,
    encodedCharCount: encodedCharCount(url),
    queryLength: parsedUrl.search.length,
  };

  return result;
}

function isIP(parsedUrl: URL): boolean {
  const hostname = parsedUrl.hostname.replace(/^\[|\]$/g, "");
  return net.isIPv4(hostname) || net.isIPv6(hostname);
}

function subdomainCount(parsedUrl: URL): number {
  if (isIP(parsedUrl) || parsedUrl.hostname === "localhost") return 0;
  return parsedUrl.hostname.split(".").length - 2;
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

export default analyzeUrl;
