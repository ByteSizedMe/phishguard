import { Router } from "express";
import { analyzeUrl } from "../services/url-analyzer.service";
import { assess } from "../services/risk-scoring.service";

const analyzeRouter = Router();

analyzeRouter.post("/", (req, res) => {
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

  const results = urls.map((url) => {
    try {
      const result = analyzeUrl(url);
      const assessment = assess(result);
      return {
        url,
        ...assessment,
      };
    } catch {
      return {
        url,
        error: "Invalid URL",
      };
    }
  });

  res.json(results);
});

export default analyzeRouter;
