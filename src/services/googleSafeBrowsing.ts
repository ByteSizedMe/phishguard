import axios from "axios";

const API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

const API_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`;

export interface GoogleThreatMatch {
  threatType: string;
}

export interface GoogleSafeBrowsingResponse {
  matches?: GoogleThreatMatch[];
}

export async function checkGoogleSafeBrowsing(url: string) {
  const requestBody = {
    client: {
      clientId: "phishguard",
      clientVersion: "1.0.0",
    },

    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [
        {
          url: url,
        },
      ],
    },
  };

  const response = await axios.post<GoogleSafeBrowsingResponse>(
    API_URL,
    requestBody,
  );

  return {
    isThreat: response.data.matches !== undefined,
    threatTypes: response.data.matches?.map((match) => match.threatType) ?? [],
  };
}
