import { Router } from "express";
import { generateApiKey } from "../services/api-key.service";
import { verifyTurnstileToken } from "../services/turnstile.service";
import { keyGenerationRateLimit } from "../middleware/key-generation-rate-limit.middleware";

const apiRouter = Router();

apiRouter.post("/", keyGenerationRateLimit, async (req, res) => {
  const { turnstileToken } = req.body;

  if (!turnstileToken || typeof turnstileToken !== "string") {
    res.status(400).json({
      error: "Turnstile verification required",
    });
    return;
  }

  try {
    const verified = await verifyTurnstileToken(turnstileToken);

    if (!verified) {
      res.status(403).json({
        error: "Turnstile verification failed",
      });
      return;
    }

    const apiKey = await generateApiKey();

    res.status(201).json({
      apiKey,
      message: "API key generated successfully. Store it securely.",
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Failed to generate API key",
    });
  }
});

export default apiRouter;
