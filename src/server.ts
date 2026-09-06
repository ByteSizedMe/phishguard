import express from "express";
import "dotenv/config";
import cors from "cors";
import analyzeRouter from "./routes/analyze.routes";
import historyRouter from "./routes/history.routes";
import apiRouter from "./routes/api-key.routes";
import keyPageRouter from "./routes/key-page.routes";

const app = express();

const PORT = Number(process.env.PORT) || 3000;

app.use(express.json());
app.use(cors());

app.use("/api/analyze", analyzeRouter);
app.use("/api/history", historyRouter);
app.use("/api/keys", apiRouter);
app.use("/get-key", keyPageRouter);

app.get("/", (req, res) => {
  res.json({
    name: "PhishGuard API",
    status: "online",
    message: "Phishing and malicious URL analysis API",
    endpoints: {
      analyze: "POST /api/analyze",
      history: "GET /api/history",
      apiKeys: "POST /api/keys",
      getKey: "GET /get-key",
    },
  });
});

app.use(
  (
    err: Error,
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) => {
    console.error(err);

    res.status(500).json({
      error: "Internal server error",
    });
  },
);

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
