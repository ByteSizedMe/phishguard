import { Router } from "express";

const keyPageRouter = Router();

keyPageRouter.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>PhishGuard API Key</title>
        <meta charset="UTF-8">
      </head>

      <body>
        <h1>PhishGuard API Key</h1>

        <p>Complete the verification below to generate an API key.</p>

        <div
          class="cf-turnstile"
          data-sitekey="${process.env.TURNSTILE_SITE_KEY}"
          data-callback="onTurnstileSuccess">
        </div>

        <button id="generate" disabled>
          Generate API Key
        </button>

        <pre id="result"></pre>

        <script>
          let turnstileToken = null;

          function onTurnstileSuccess(token) {
            turnstileToken = token;
            document.getElementById("generate").disabled = false;
          }

          document.getElementById("generate").addEventListener("click", async () => {
            const result = document.getElementById("result");

            result.textContent = "Generating...";

            try {
              const response = await fetch("/api/keys", {
                method: "POST",
                headers: {
                  "Content-Type": "application/json"
                },
                body: JSON.stringify({
                  turnstileToken
                })
              });

              const data = await response.json();

              if (!response.ok) {
                result.textContent = data.error || "Failed to generate API key";
                return;
              }

              result.textContent =
                "API Key:\\n\\n" +
                data.apiKey +
                "\\n\\nStore this key securely. It will not be shown again.";
            } catch {
              result.textContent = "Request failed.";
            }
          });
        </script>

        <script
          src="https://challenges.cloudflare.com/turnstile/v0/api.js"
          async
          defer>
        </script>
      </body>
    </html>
  `);
});

export default keyPageRouter;
