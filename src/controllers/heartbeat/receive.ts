import { Request, Response, NextFunction } from "express";
import db from "../../config/db";
import logger from "../../utils/logger";

export const receiveHeartbeat = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { client_id, service, timestamp, status, metadata } = req.body;

    // Validación básica
    if (
      typeof client_id !== 'string' ||
      typeof service !== 'string' ||
      typeof timestamp !== 'string' ||
      typeof status !== 'string'
    ) {
      logger.warn("[/api/heartbeat] Invalid payload", { body: req.body });
      return res.status(400).json({ error: "Invalid payload structure" });
    }

    const ts = new Date(timestamp);
    if (isNaN(ts.getTime())) {
      return res.status(400).json({ error: "Invalid timestamp format" });
    }

    const query = `
      INSERT INTO heartbeats (
        client_id, service, timestamp, status, metadata
      ) VALUES ($1, $2, $3, $4, $5)
    `;

    const values = [
      client_id,
      service,
      ts,
      status,
      metadata ? JSON.stringify(metadata) : null
    ];

    await db.query(query, values);

    return res.status(200).json({ received: true });
  } catch (err) {
    logger.error("[/api/heartbeat] Internal error", { err });
    return res.status(500).json({ error: "Internal server error" });
  }
};
