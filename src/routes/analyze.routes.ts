import { Router } from "express";
import { analyzeUrl } from "../services/url-analyzer.service";
import { assess } from "../services/risk-scoring.service";
import { checkGoogleSafeBrowsing } from "../services/googleSafeBrowsing";
import { checkURLhaus, checkURLhausHost } from "../services/urlhaus";

const analyzeRouter = Router();

analyzeRouter.post("/", async (req, res) => {
  const urls = req.body.urls;

  if (urls == null) {
    res.status(400).json({ error: "URLs are required" });
    return;
  }

  if (!Array.isArray(urls)) {
    res.status(400).json({ error: "URLs must be an array" });
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
        return {
          url,
          error: "Invalid URL",
        };
      }

      try {
        const [googleResult, urlhausResult, urlhausHostResult] =
          await Promise.all([
            checkGoogleSafeBrowsing(url),
            checkURLhaus(url),
            checkURLhausHost(url),
          ]);

        const assessment = assess(
          result,
          googleResult,
          urlhausResult,
          urlhausHostResult,
        );

        return {
          url,
          ...assessment,
        };
      } catch {
        return {
          url,
          error: "Reputation check failed",
        };
      }
    }),
  );

  res.json(results);
});

export default analyzeRouter;
