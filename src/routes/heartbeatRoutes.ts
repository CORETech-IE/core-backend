/**
 * ?? CORE-BACKEND: Heartbeat Routes
 */

import express from 'express';
import { authenticateRequest } from '../middlewares/authentication';
import { 
  sendHeartbeat, 
  getServiceStatus, 
  getAllServicesStatus 
} from '../controllers/heartbeat/receive';

const router = express.Router();

// Send heartbeat (requires auth)
router.post('/', authenticateRequest, sendHeartbeat);

// Get all services status (public)
router.get('/', getAllServicesStatus);

// Get specific service status (public)
router.get('/:service', getServiceStatus);

export default router;