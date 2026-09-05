import { Router } from "express";
import { authenticateApiKey } from "../middleware/api-key.middleware";
import { getHistory } from "../services/analysis-history.service";

const historyRouter = Router();

historyRouter.get("/", authenticateApiKey, async (req, res) => {
  try {
    const history = await getHistory(req.apiKeyId!);

    res.json(history);
  } catch {
    res.status(500).json({
      error: "Failed to retrieve analysis history",
    });
  }
});

export default historyRouter;
