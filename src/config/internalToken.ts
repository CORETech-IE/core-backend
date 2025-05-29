import jwt from 'jsonwebtoken';

const SECRET = process.env.JWT_SECRET || 'default_secret_dangerous';

export const getInternalToken = (): string => {
  return jwt.sign(
    { username: 'core_services', role: 'admin' },
    SECRET,
    { expiresIn: '1h' }
  );
};
