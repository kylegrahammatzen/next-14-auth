"use server";

import { SignJWT, jwtVerify } from "jose";
import { nanoid } from "nanoid";

const JWT_AUTH_KEY = process.env.JWT_AUTH_KEY;
if (!JWT_AUTH_KEY) {
  throw new Error("JWT_AUTH_KEY is not set");
}

interface TokenPayload {
  id: string;
  userId: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: string;
  [key: string]: any;
}

export async function verifyToken(token: string): Promise<TokenPayload> {
  const result = await jwtVerify(token, new TextEncoder().encode(JWT_AUTH_KEY));
  return result.payload as TokenPayload;
}

export async function signToken(payload: Record<string, any>): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setJti(nanoid())
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(new TextEncoder().encode(JWT_AUTH_KEY));
}
