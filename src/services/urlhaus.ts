import axios from "axios";

const AUTH_KEY = process.env.URLHAUS_AUTH_KEY;

const API_URL = "https://urlhaus-api.abuse.ch/v1/url/";
const API_URL_HOST = "https://urlhaus-api.abuse.ch/v1/host/";

export interface URLhausUrlResponse {
  query_status: "ok" | "no_results";
  url_status?: "online" | "offline";
  threat?: string;
}

export interface URLhausMatchedUrl {
  id: string;
  url: string;
  url_status: "online" | "offline";
  threat: string;
  date_added: string;
  reporter: string;
  takedown_time: string | null;
  query_status?: string;
}

export interface URLhausHostResponse {
  query_status: "ok" | "no_match" | "invalid_host";
  urlhaus_reference?: string;
  firstseen?: string;
  url_count?: number;
  blacklists?: {
    spamhaus_dbl: string;
    surbl: string;
  };
  urls?: URLhausMatchedUrl[];
}

export async function checkURLhaus(url: string) {
  const response = await axios.post<URLhausUrlResponse>(
    API_URL,
    new URLSearchParams({
      url: url,
    }),
    {
      headers: {
        "Auth-Key": AUTH_KEY,
        "Content-Type": "application/x-www-form-urlencoded",
      },
    },
  );

  return {
    isMalicious: response.data.query_status === "ok",
    threat: response.data.threat ?? null,
    urlStatus: response.data.url_status ?? null,
  };
}

export async function checkURLhausHost(url: string) {
  try {
    const parsedUrl = new URL(url);
    const hostName = parsedUrl.hostname;

    const response = await axios.post<URLhausHostResponse>(
      API_URL_HOST,
      new URLSearchParams({
        host: hostName,
      }),
      {
        headers: {
          "Auth-Key": AUTH_KEY,
          "Content-Type": "application/x-www-form-urlencoded",
        },
      },
    );

    return {
      isMalicious: response.data.query_status === "ok",
      urlCount: response.data.url_count ?? 0,
      blacklists: response.data.blacklists ?? null,
      matchedUrls: response.data.urls ?? [],
    };
  } catch (error) {
    console.error("URLhaus host lookup failed:", error);
    throw error;
  }
}
