import express from "express";
import { generateLogEmitter } from "../controllers/log/emitter";
import { authenticateJWT } from "../middlewares/auth";
import { authorizeAdmin } from "../middlewares/authorizeAdmin";
import { receiveMetrics } from "../controllers/metrics/receive";
//import { receiveHeartbeat } from "../controllers/heartbeat/receive";

const configureRouter = (app: express.Application) => {
  app.get("/health", (req, res) => {
    res.status(200).json({ status: "ok", timestamp: new Date().toISOString() });
  });

  // Define the routes for PDF, ZPL, email, and log generation
  // These routes are protected by JWT authentication and admin authorization
  // The authenticateJWT middleware checks the JWT token in the request header
  // The authorizeAdmin middleware checks if the user has admin privileges


  // Route to emit logs
  app.post("/emit-log", authenticateJWT, authorizeAdmin, generateLogEmitter);

  // Route to receive metrics
  // This route allows clients to send metrics data to the server
  // The receiveMetrics controller processes the incoming metrics data
  app.post("/api/metrics", authenticateJWT, authorizeAdmin, receiveMetrics);

  // Route to receive heartbeat signals
  // This route allows services to send heartbeat signals to the server
  // The receiveHeartbeat controller processes the incoming heartbeat data
  //app.post("/api/heartbeat", authenticateJWT, authorizeAdmin, receiveHeartbeat);

};

export default configureRouter;
