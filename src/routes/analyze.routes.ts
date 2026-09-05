import { Router } from "express";
import { analyzeUrl } from "../services/url-analyzer.service";
import { assess } from "../services/risk-scoring.service";
import { checkGoogleSafeBrowsing } from "../services/googleSafeBrowsing";
import { checkURLhaus, checkURLhausHost } from "../services/urlhaus";
import { checkTyposquatting } from "../services/typosquatting.service";
import rateLimit from "express-rate-limit";
import { authenticateApiKey } from "../middleware/api-key.middleware";

const analyzeLimiter = rateLimit({
  windowMs: 900000,
  limit: 100,
  handler: (req, res) => {
    res.status(429).json({ error: "Too many requests" });
  },
});

const BATCH_LIMIT = 20;

const analyzeRouter = Router();

analyzeRouter.post(
  "/",
  analyzeLimiter,
  authenticateApiKey,
  async (req, res) => {
    const urls = req.body.urls;

    if (urls == null) {
      res.status(400).json({ error: "URLs are required" });
      return;
    }
    if (!Array.isArray(urls)) {
      res.status(400).json({ error: "URLs must be an array" });
      return;
    }
    if (urls.length > BATCH_LIMIT) {
      res.status(400).json({ error: "Too many URLs in a single request" });
      return;
    }
    if (urls.length === 0) {
      res.status(400).json({ error: "URL list is empty" });
      return;
    }
    if (urls.some((url) => typeof url !== "string")) {
      res.status(400).json({ error: "Every URL must be a string" });
      return;
    }
    if (urls.some((url) => url.trim() === "")) {
      res.status(400).json({ error: "URL cannot be empty" });
      return;
    }

    const results = await Promise.all(
      urls.map(async (url) => {
        let result;
        try {
          result = analyzeUrl(url);
        } catch {
          return { url, error: "Invalid URL" };
        }

        const typosquattingResult = checkTyposquatting(result.originalHostname);
        let googleResult;
        let urlhausResult;
        let urlhausHostResult;

        try {
          [googleResult, urlhausResult, urlhausHostResult] = await Promise.all([
            checkGoogleSafeBrowsing(url),
            checkURLhaus(url),
            checkURLhausHost(url),
          ]);
        } catch {
          return { url, error: "Reputation check failed" };
        }

        const assessment = await assess(
          result,
          typosquattingResult,
          googleResult,
          urlhausResult,
          urlhausHostResult,
          req.apiKeyId!,
        );

        return { url, ...assessment };
      }),
    );

    res.json(results);
  },
);

export default analyzeRouter;
