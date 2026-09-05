import pool from "./database";

export async function saveAnalysis(
  url: string,
  score: number,
  level: string,
  apiKeyId: number,
) {
  await pool.query(
    `INSERT INTO analysis_history (url, score, level, api_key_id)
     VALUES ($1, $2, $3, $4)`,
    [url, score, level, apiKeyId],
  );
}

export async function getHistory(apiKeyId: number) {
  const result = await pool.query(
    `SELECT id, url, score, level, analyzed_at
     FROM analysis_history
     WHERE api_key_id = $1
     ORDER BY analyzed_at DESC`,
    [apiKeyId],
  );

  return result.rows;
}
