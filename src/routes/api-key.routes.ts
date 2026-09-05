import { Router } from "express";
import { generateApiKey } from "../services/api-key.service";

const apiRouter = Router();

apiRouter.post("/", async (req, res) => {
  try {
    const apiKey = await generateApiKey();
    res.json(apiKey);
  } catch (error) {
    console.error("API key generation failed:", error);
    res.status(500).json({
      error: "Failed to generate API key",
    });
  }
});

export default apiRouter;
