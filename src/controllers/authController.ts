import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import rawUsers from '../config/users.json';

// Define the shape of each user record
interface UserRecord {
  password: string;  // hashed password
  role: string;      // user role, e.g., 'admin', 'viewer'
}

// Apply type to the users object
const users: Record<string, UserRecord> = rawUsers;

// Load JWT secret from environment
const SECRET = process.env.JWT_SECRET || 'default_secret_dangerous';

export const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;

  // Validate input presence
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const user = users[username];

  // Check if user exists
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Validate password using bcrypt
  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Generate JWT token with role
  const token = jwt.sign({ username, role: user.role }, SECRET, { expiresIn: '15m' });

  // Return the token to the client
  res.json({ token });
};
