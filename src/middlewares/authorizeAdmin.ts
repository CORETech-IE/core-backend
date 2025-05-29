// Middleware to enforce that only users with role "admin" can access a route
import { Request, Response, NextFunction } from 'express';

export const authorizeAdmin = (req: Request, res: Response, next: NextFunction) => {
  const user = (req as any).user;

  if (!user || user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: admin access required' });
  }

  next();
};
