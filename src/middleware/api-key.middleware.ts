import { Request, Response, NextFunction } from "express";
import bcrypt from "bcrypt";
import pool from "../services/database";

export async function authenticateApiKey(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(401).json({
      error: "API key required",
    });
    return;
  }

  const apiKey = authHeader.substring(7);

  try {
    const result = await pool.query(
      `SELECT id, key_hash
       FROM api_keys`,
    );

    for (const row of result.rows) {
      const isValid = await bcrypt.compare(apiKey, row.key_hash);

      if (isValid) {
        req.apiKeyId = row.id;
        next();
        return;
      }
    }

    res.status(401).json({
      error: "Invalid API key",
    });
  } catch {
    res.status(500).json({
      error: "Authentication failed",
    });
  }
}
