import crypto from "crypto";
import bcrypt from "bcrypt";

import pool from "./database";

export async function generateApiKey(): Promise<string> {
  const apiKey = crypto.randomBytes(32).toString("hex");

  const keyHash = await bcrypt.hash(apiKey, 12);

  await pool.query(
    `INSERT INTO api_keys (key_hash)
     VALUES ($1)`,
    [keyHash],
  );

  return apiKey;
}
