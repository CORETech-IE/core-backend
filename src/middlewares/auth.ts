import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

// Secret key used to sign and verify JWTs
const SECRET = process.env.JWT_SECRET || 'default_secret_dangerous';

// Middleware to authenticate requests using JWT
export const authenticateJWT = (req: Request, res: Response, next: NextFunction) => {
  // Read the Authorization header from the request
  const authHeader = req.headers.authorization;

  // Check if the header exists and follows the Bearer token format
  if (authHeader && authHeader.startsWith('Bearer ')) {
    // Extract the token from the header
    const token = authHeader.split(' ')[1];

    // Verify the token using the configured secret
    jwt.verify(token, SECRET, (err, user) => {
      if (err) {
        // Token is invalid or expired
        return res.status(403).json({ error: 'Invalid or expired token' });
      }

      // Token is valid; attach user info to the request object
      (req as any).user = user;

      // Proceed to the next middleware or route handler
      next();
    });
  } else {
    // Authorization header is missing or not formatted correctly
    return res.status(401).json({ error: 'Authorization header missing or malformed' });
  }
};
