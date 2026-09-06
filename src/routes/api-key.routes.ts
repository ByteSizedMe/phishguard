import { Router } from "express";
import { generateApiKey } from "../services/api-key.service";

const apiRouter = Router();

apiRouter.post("/", async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({ error: "Admin API key required" });
    return;
  }

  const providedKey = authHeader.substring(7);

  if (!process.env.ADMIN_API_KEY || providedKey !== process.env.ADMIN_API_KEY) {
    res.status(401).json({ error: "Invalid admin API key" });
    return;
  }

  try {
    const apiKey = await generateApiKey();
    res.json({ apiKey });
  } catch {
    res.status(500).json({ error: "Failed to generate API key" });
  }
});

export default apiRouter;
