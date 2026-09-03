import { SuspiciousEncoding, UrlAnalysis } from "./url-analyzer.service";
import { parse } from "tldts";

export interface RiskAssessment {
  score: number;
  level: string;
  signals: RiskSignal[];
}

export interface RiskSignal {
  feature: string;
  message: string;
  points: number;
}

const baselines = new Map<string, number>([
  ["url", 0],
  ["protocol", 0],
  ["hostname", 0],
  ["pathname", 0],
  ["port", 0],
  ["search", 0],
  ["hash", 0],

  ["urlLength", 75],
  ["subdomainCount", 2],
  ["isIpAddress", 0],
  ["hostnameLength", 30],
  ["pathnameLength", 50],
  ["digitCount", 2],
  ["isHttps", 0],
  ["specialCharCount", 2],
  ["hyphenCount", 2],
  ["dotCount", 2],
  ["encodedCharCount", 2],
  ["queryLength", 50],
]);

const maximums = new Map<string, number>([
  ["url", 0],
  ["protocol", 0],
  ["hostname", 0],
  ["pathname", 0],
  ["port", 0],
  ["search", 0],
  ["hash", 0],

  ["urlLength", 200],
  ["subdomainCount", 5],
  ["isIpAddress", 1],
  ["hostnameLength", 60],
  ["pathnameLength", 150],
  ["digitCount", 8],
  ["isHttps", 1],
  ["specialCharCount", 8],
  ["hyphenCount", 6],
  ["dotCount", 5],
  ["encodedCharCount", 10],
  ["queryLength", 200],
]);

const maxPoints = new Map<string, number>([
  ["url", 0],
  ["protocol", 0],
  ["hostname", 0],
  ["pathname", 0],
  ["port", 0],
  ["search", 0],
  ["hash", 0],

  ["urlLength", 4],
  ["subdomainCount", 4],
  ["isIpAddress", 8],
  ["hostnameLength", 3],
  ["pathnameLength", 2],
  ["digitCount", 3],
  ["isHttps", 0],
  ["specialCharCount", 3],
  ["hyphenCount", 2],
  ["dotCount", 0],
  ["encodedCharCount", 3],
  ["queryLength", 2],
]);

function normalize(value: number, baseline: number, max: number): number {
  const result = (value - baseline) / (max - baseline);
  if (result < 0) return 0;
  return Math.min(result, 1);
}

export function assess(UrlData: UrlAnalysis): RiskAssessment {
  const signals = [
    checkIpAddress(UrlData.isIpAddress),
    checkAtSymbol(UrlData.url, UrlData.username),
    checkLength("urlLength", UrlData.urlLength),
    checkLength("hostnameLength", UrlData.hostnameLength),
    checkLength("pathnameLength", UrlData.pathnameLength),
    checkLength("queryLength", UrlData.queryLength),
    checkCount("subdomainCount", UrlData.subdomainCount),
    checkCount("digitCount", UrlData.digitCount),
    checkCount("specialCharCount", UrlData.specialCharCount),
    checkCount("hyphenCount", UrlData.hyphenCount),
    checkCount("encodedCharCount", UrlData.encodedCharCount),
    checkSusTld(UrlData.tld),
    checkParams(UrlData.parsedUrl, UrlData.redirectParams),
    checkSusKeywords(UrlData.parsedUrl),
    checkEntropy(UrlData.hostname),
    checkPunycode(UrlData.hasPunyCode),
    ...checkDoubleEncoding(UrlData.doubleEncodedCharCount),
    checkSuspiciousEncoding(UrlData.suspiciousEncoding),
  ].filter((signal): signal is RiskSignal => signal !== null);

  const score = signals.reduce((total, signal) => total + signal.points, 0);

  let level: string;

  if (score <= 7) {
    level = "Low";
  } else if (score <= 14) {
    level = "Suspicious";
  } else if (score <= 22) {
    level = "High";
  } else {
    level = "Very High";
  }

  return {
    score,
    level,
    signals,
  };
}

function checkIpAddress(isIp: boolean): RiskSignal | null {
  const value = isIp ? 1 : 0;
  const baseline = baselines.get("isIpAddress")!;
  const maximum = maximums.get("isIpAddress")!;
  const maxP = maxPoints.get("isIpAddress")!;
  const norm = normalize(value, baseline, maximum);
  let message = "";

  if (value === 1) {
    message = "URL contains IP address";

    return {
      feature: "isIpAddress",
      message: message,
      points: norm * maxP,
    };
  }

  return null;
}

function checkAtSymbol(url: string, username: string): RiskSignal | null {
  if (!url.includes("@")) {
    return null;
  }

  if (/^[^@]+\.[a-zA-Z]{2,}$/.test(username)) {
    return {
      feature: "hostnameLikeUserInfo",
      message:
        "URL contains text resembling a hostname before @, which may obscure the actual destination",
      points: 8,
    };
  }

  if (username !== "") {
    return {
      feature: "userInfo",
      message: "URL contains user information before the hostname",
      points: 5,
    };
  }

  return {
    feature: "atSymbol",
    message: "URL contains an @ symbol",
    points: 1,
  };
}

function checkSusTld(tld: string): RiskSignal | null {
  const susTlds = [
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
  if (susTlds.includes(tld)) {
    const message = "URL contains suspicious TLD";
    const points = 3;
    return {
      feature: "suspiciousTld",
      message: message,
      points: points,
    };
  }
  return null;
}

function checkParams(
  parsedUrl: URL,
  params: URLSearchParams,
): RiskSignal | null {
  const redirectParams = new Set([
    "redirect",
    "redirect_url",
    "redirect_uri",
    "next",
    "return",
    "return_url",
    "returnurl",
    "continue",
    "destination",
  ]);
  const urlParams = new Set(["url", "uri", "dest", "target", "target_url"]);
  let score = 0;
  let message = "";
  let feature = "";

  for (const [key, value] of params) {
    const normalizedKey = key.toLowerCase();
    if (redirectParams.has(normalizedKey)) {
      const redirectUrl = new URL(value, parsedUrl.origin);
      if (redirectUrl.hostname !== parsedUrl.hostname && score < 4) {
        score = 4;
        message =
          "URL contains a redirect parameter pointing to an external destination";
      } else if (redirectUrl.hostname === parsedUrl.hostname && score < 1) {
        score = 1;
        message =
          "URL contains a redirect parameter pointing to an internal destination";
      }
      feature = "redirectParameters";
    } else if (urlParams.has(normalizedKey)) {
      const redirectUrl = new URL(value, parsedUrl.origin);
      if (redirectUrl.hostname !== parsedUrl.hostname && score < 2) {
        score = 2;
        message = "URL parameter references an external destination";
        feature = "externalUrlParameter";
      }
    }
  }

  if (message === "") return null;

  return {
    feature: feature,
    message: message,
    points: score,
  };
}

function checkSusKeywords(parsedUrl: URL): RiskSignal | null {
  const suspiciousKeywords = new Set([
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "credential",
    "payment",
    "billing",
    "bank",
    "wallet",
    "unlock",
    "suspended",
  ]);
  const hostname = parsedUrl.hostname.toLowerCase();
  const pathname = parsedUrl.pathname.toLowerCase();
  let hostScore = 0;
  let pathScore = 0;
  let message = "";
  let feature = "";

  suspiciousKeywords.forEach((key: string) => {
    if (hostname.includes(key)) {
      hostScore = 3;
    }
    if (pathname.includes(key)) {
      pathScore = 1;
    }
  });

  if (hostScore !== 0) {
    if (pathScore !== 0) {
      message = "Hostname and pathname contain suspicious keywords";
    } else message = "Hostname contains suspicious keywords";
    feature = "hostnameSuspiciousKeywords";
  } else if (pathScore !== 0) {
    message = "Pathname contains suspicious keywords";
    feature = "pathnameSuspiciousKeywords";
  }

  if (message === "") return null;

  return {
    feature: feature,
    message: message,
    points: hostScore + pathScore,
  };
}

function checkEntropy(hostname: string): RiskSignal | null {
  const value = parse(hostname);
  if (value.domain === null) return null;
  const freq = new Map<string, number>();
  const length = hostname.replaceAll(".", "").length;
  let entropy = 0;
  let points = 0;
  const feature = "hostnameEntropy";
  let message = "";

  for (const char of hostname) {
    if (char !== ".") {
      if (!freq.has(char)) freq.set(char, 1);
      else freq.set(char, freq.get(char)! + 1);
    }
  }

  for (const [key, value] of freq) {
    const p = value / length;
    entropy += -p * Math.log2(p);
  }

  if (entropy >= 3 && entropy <= 3.5) {
    points = 1;
    message = "Hostname has slightly elevated character entropy";
  } else if (entropy > 3.5 && entropy <= 4) {
    points = 2;
    message = "Hostname has moderately high character entropy";
  } else if (entropy > 4 && entropy <= 4.5) {
    points = 3;
    message =
      "Hostname has high character entropy, suggesting a potentially obfuscated or randomly generated name";
  } else if (entropy > 4.5) {
    points = 4;
    message =
      "Hostname has unusually high character entropy, suggesting a potentially obfuscated or randomly generated name";
  }

  if (message === "") return null;

  return {
    feature: feature,
    message: message,
    points: points,
  };
}

function checkPunycode(hasPunycode: boolean): RiskSignal | null {
  if (!hasPunycode) return null;

  return {
    feature: "punycode",
    message: "Hostname contains a Punycode-encoded domain label",
    points: 5,
  };
}

function checkDoubleEncoding(map: {
  hostname: number;
  pathname: number;
  query: number;
  username: number;
  password: number;
}): RiskSignal[] {
  const signals: RiskSignal[] = [];

  if (map.hostname > 0) {
    signals.push({
      feature: "doubleEncoding",
      message: `Hostname contains ${map.hostname} double-encoded characters`,
      points: 4,
    });
  }

  if (map.pathname > 0) {
    signals.push({
      feature: "doubleEncoding",
      message: `Pathname contains ${map.pathname} double-encoded characters`,
      points: 2,
    });
  }

  if (map.query > 0) {
    signals.push({
      feature: "doubleEncoding",
      message: `Query contains ${map.query} double-encoded characters`,
      points: 2,
    });
  }

  if (map.username > 0) {
    signals.push({
      feature: "doubleEncoding",
      message: `Username contains ${map.username} double-encoded characters`,
      points: 3,
    });
  }

  if (map.password > 0) {
    signals.push({
      feature: "doubleEncoding",
      message: `Password contains ${map.password} double-encoded characters`,
      points: 3,
    });
  }

  return signals;
}

function checkSuspiciousEncoding(
  suspiciousEncoding: SuspiciousEncoding[],
): RiskSignal | null {
  if (suspiciousEncoding.length === 0) {
    return null;
  }

  let userScore = 0;
  let passScore = 0;

  suspiciousEncoding.forEach((susEnc: SuspiciousEncoding) => {
    const encoding = susEnc.encoding.toLowerCase();
    if (susEnc.location === "username") {
      if (encoding === "%2f" || encoding === "%3f" || encoding === "%23")
        userScore = Math.min(userScore + 3, 4);
      else if (encoding === "%40") userScore = Math.min(userScore + 4, 4);
    } else if (susEnc.location === "password") {
      if (encoding === "%2f" || encoding === "%3f" || encoding === "%23")
        passScore = Math.min(passScore + 3, 4);
      else if (encoding === "%40") passScore = Math.min(passScore + 4, 4);
    }
  });

  if (userScore === 0 && passScore === 0) return null;

  return {
    feature: "suspiciousEncoding",
    message: "URL contains suspicious encoded characters",
    points: userScore + passScore,
  };
}

function checkLength(feature: string, length: number): RiskSignal | null {
  const baseline = baselines.get(feature)!;
  const maximum = maximums.get(feature)!;
  const maxP = maxPoints.get(feature)!;
  const norm = normalize(length, baseline, maximum);
  let message = "";

  if (feature === "urlLength") {
    if (length >= 76 && length <= 150) message = "URL is unusually long";
    else if (length > 150) message = "URL is excessively long";
  } else if (feature === "hostnameLength") {
    if (length >= 31 && length <= 45) message = "Hostname is unusually long";
    else if (length > 45) message = "Hostname is excessively long";
  } else if (feature === "pathnameLength") {
    if (length >= 51 && length <= 100) message = "Pathname is unusually long";
    else if (length > 100) message = "Pathname is excessively long";
  } else if (feature === "queryLength") {
    if (length >= 51 && length <= 125) message = "Query is unusually long";
    else if (length > 125) message = "Query is excessively long";
  }

  if (message.length != 0) {
    return {
      feature: feature,
      message: message,
      points: norm * maxP,
    };
  }

  return null;
}

function checkCount(feature: string, count: number): RiskSignal | null {
  const baseline = baselines.get(feature)!;
  const maximum = maximums.get(feature)!;
  const maxP = maxPoints.get(feature)!;
  const norm = normalize(count, baseline, maximum);
  let message = "";

  if (feature === "subdomainCount") {
    if (count === 3)
      message = "URL contains an unusually high number of subdomains";
    else if (count > 3)
      message = "URL contains a very high number of subdomains";
  } else if (feature === "digitCount") {
    if (count >= 3 && count <= 5)
      message = "Hostname contains an unusual number of digits";
    else if (count > 5) message = "Hostname contains a high number of digits";
  } else if (feature === "specialCharCount") {
    if (count >= 3 && count <= 5)
      message = "URL contains an unusual number of special characters";
    else if (count > 5)
      message = "URL contains a high number of special characters";
  } else if (feature === "hyphenCount") {
    if (count >= 3 && count <= 4)
      message = "URL contains an unusual number of hyphens";
    else if (count > 4) message = "URL contains a high number of hyphens";
  } else if (feature === "encodedCharCount") {
    if (count >= 3 && count <= 6)
      message = "URL contains an unusual amount of encoded data";
    else if (count > 6) message = "URL contains a high amount of encoded data";
  }

  if (message.length != 0) {
    return {
      feature: feature,
      message: message,
      points: norm * maxP,
    };
  }

  return null;
}
