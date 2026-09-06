import rateLimit from "express-rate-limit";

export const keyGenerationRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 3,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "Too many API key generation attempts. Try again later.",
  },
});
