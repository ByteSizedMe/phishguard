export interface LegitimateDomain {
  domain: string;
  brand: string;
}

export const legitimateDomains: LegitimateDomain[] = [
  // Search / Technology
  { domain: "google.com", brand: "Google" },
  { domain: "microsoft.com", brand: "Microsoft" },
  { domain: "apple.com", brand: "Apple" },
  { domain: "amazon.com", brand: "Amazon" },
  { domain: "openai.com", brand: "OpenAI" },
  { domain: "adobe.com", brand: "Adobe" },
  { domain: "cloudflare.com", brand: "Cloudflare" },

  // Microsoft / Google services
  { domain: "office.com", brand: "Microsoft Office" },
  { domain: "outlook.com", brand: "Microsoft Outlook" },
  { domain: "live.com", brand: "Microsoft" },

  // Developer / Cloud
  { domain: "github.com", brand: "GitHub" },
  { domain: "gitlab.com", brand: "GitLab" },
  { domain: "bitbucket.org", brand: "Bitbucket" },
  { domain: "npmjs.com", brand: "npm" },

  // Payments / Finance
  { domain: "paypal.com", brand: "PayPal" },
  { domain: "stripe.com", brand: "Stripe" },
  { domain: "visa.com", brand: "Visa" },
  { domain: "mastercard.com", brand: "Mastercard" },
  { domain: "americanexpress.com", brand: "American Express" },
  { domain: "chase.com", brand: "Chase" },
  { domain: "bankofamerica.com", brand: "Bank of America" },
  { domain: "wellsfargo.com", brand: "Wells Fargo" },

  // Social Media
  { domain: "facebook.com", brand: "Facebook" },
  { domain: "instagram.com", brand: "Instagram" },
  { domain: "linkedin.com", brand: "LinkedIn" },
  { domain: "twitter.com", brand: "Twitter" },
  { domain: "x.com", brand: "X" },
  { domain: "youtube.com", brand: "YouTube" },
  { domain: "tiktok.com", brand: "TikTok" },
  { domain: "snapchat.com", brand: "Snapchat" },
  { domain: "whatsapp.com", brand: "WhatsApp" },
  { domain: "telegram.org", brand: "Telegram" },
  { domain: "discord.com", brand: "Discord" },
  { domain: "reddit.com", brand: "Reddit" },

  // Streaming / Entertainment
  { domain: "netflix.com", brand: "Netflix" },
  { domain: "spotify.com", brand: "Spotify" },
  { domain: "steam.com", brand: "Steam" },

  // Cloud Storage / Productivity
  { domain: "dropbox.com", brand: "Dropbox" },
  { domain: "notion.so", brand: "Notion" },
  { domain: "slack.com", brand: "Slack" },
  { domain: "zoom.us", brand: "Zoom" },
  { domain: "docusign.com", brand: "DocuSign" },

  // Shopping / E-commerce
  { domain: "ebay.com", brand: "eBay" },
  { domain: "walmart.com", brand: "Walmart" },
  { domain: "shopify.com", brand: "Shopify" },
  { domain: "etsy.com", brand: "Etsy" },
  { domain: "aliexpress.com", brand: "AliExpress" },

  // Other high-value targets
  { domain: "uber.com", brand: "Uber" },
  { domain: "airbnb.com", brand: "Airbnb" },
  { domain: "booking.com", brand: "Booking.com" },
  { domain: "indeed.com", brand: "Indeed" },
  { domain: "canva.com", brand: "Canva" },
  { domain: "salesforce.com", brand: "Salesforce" },
  { domain: "atlassian.com", brand: "Atlassian" },
];
