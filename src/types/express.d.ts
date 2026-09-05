declare global {
  namespace Express {
    interface Request {
      apiKeyId?: number;
    }
  }
}

export {};
