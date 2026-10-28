import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import type { User } from '../src/types.js';

// Secret key for HMAC token signing (using env or persistent server seed)
const TOKEN_SECRET = process.env.JWT_SECRET || 'phishguard_secure_token_secret_2026_key';

export interface AuthenticatedRequest extends Request {
  user?: User;
}

/**
 * Derives cryptographic salt + hash using PBKDF2
 */
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.pbkdf2Sync(password, salt, 10000, 32, 'sha256').toString('hex');
  return `${salt}:${derivedKey}`;
}

/**
 * Verifies password against PBKDF2 hash safely using timingSafeEqual
 */
export function verifyPassword(password: string, storedHash: string): boolean {
  if (!storedHash || !storedHash.includes(':')) return false;
  try {
    const [salt, key] = storedHash.split(':');
    const derivedKey = crypto.pbkdf2Sync(password, salt, 10000, 32, 'sha256').toString('hex');
    const keyBuf = Buffer.from(key, 'hex');
    const derivedBuf = Buffer.from(derivedKey, 'hex');
    if (keyBuf.length !== derivedBuf.length) return false;
    return crypto.timingSafeEqual(keyBuf, derivedBuf);
  } catch {
    return false;
  }
}

/**
 * Creates tamper-proof signed bearer token
 */
export function generateToken(user: Omit<User, 'password_hash'>): string {
  const payload = {
    sub: user.id,
    name: user.name,
    email: user.email,
    username: user.username,
    role: user.role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60, // 7 days
  };

  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', TOKEN_SECRET).update(encodedPayload).digest('base64url');
  return `${encodedPayload}.${signature}`;
}

/**
 * Validates and decodes bearer token
 */
export function decodeToken(token: string): User | null {
  if (!token || !token.includes('.')) return null;
  try {
    const [encodedPayload, signature] = token.split('.');
    const expectedSig = crypto.createHmac('sha256', TOKEN_SECRET).update(encodedPayload).digest('base64url');

    const sigBuf = Buffer.from(signature, 'utf8');
    const expBuf = Buffer.from(expectedSig, 'utf8');
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }

    const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'));
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) {
      return null; // Expired
    }

    return {
      id: payload.sub,
      name: payload.name,
      email: payload.email,
      username: payload.username,
      role: payload.role || 'user',
      created_at: new Date(payload.iat * 1000).toISOString(),
    };
  } catch {
    return null;
  }
}

/**
 * Middleware: Requires valid authentication token
 */
export function authenticateToken(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

  if (!token) {
    res.status(401).json({ error: 'Authentication required. Missing Bearer token.' });
    return;
  }

  const user = decodeToken(token);
  if (!user) {
    res.status(403).json({ error: 'Invalid, forged, or expired token.' });
    return;
  }

  req.user = user;
  next();
}

/**
 * Middleware: Optional authentication (attaches user if present, proceeds otherwise)
 */
export function optionalAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;

  if (token) {
    const user = decodeToken(token);
    if (user) {
      req.user = user;
    }
  }

  next();
}

/**
 * Middleware: Requires admin role
 */
export function requireAdmin(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  if (!req.user || req.user.role !== 'admin') {
    res.status(403).json({ error: 'Administrative privileges required for this endpoint.' });
    return;
  }
  next();
}
