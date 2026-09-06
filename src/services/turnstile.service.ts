import axios from "axios";

export async function verifyTurnstileToken(token: string): Promise<boolean> {
  const secret = process.env.TURNSTILE_SECRET_KEY;

  if (!secret) {
    throw new Error("TURNSTILE_SECRET_KEY is not configured");
  }

  const response = await axios.post(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    {
      secret,
      response: token,
    },
  );

  return response.data.success === true;
}
