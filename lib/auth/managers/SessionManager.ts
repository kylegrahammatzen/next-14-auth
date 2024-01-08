"use server";

import crypto from "crypto";
import { db } from "@/lib/db";
import { sessions, users } from "@/lib/db/schema";
import { cookies } from "next/headers";
import { NextResponse, type NextRequest } from "next/server";
import { eq, and } from "drizzle-orm";
import { v4 as uuidv4 } from "uuid";
import { signToken, verifyToken } from "@/lib/auth/utils/JWTHandler";

const APP_KEY = String(process.env.APP_KEY);
const AUTH_KEY = process.env.AUTH_KEY;

export async function generateToken() {
  const randomBytes = crypto.randomBytes(16);
  const token = randomBytes.toString("hex");

  const hash = crypto.createHmac("sha256", APP_KEY).update(token).digest("hex");

  return hash;
}

export async function createSession(userId: string) {
  // Check if the user exists in the database
  const userResult = await db
    .select()
    .from(users)
    .where(eq(users.id, userId))
    .limit(1)
    .execute();

  if (userResult.length === 0) {
    return {
      status: "error",
      message: "User not found",
    };
  }

  // Generate a new session
  const sessionId = uuidv4();
  const accessToken = generateToken();
  const refreshToken = generateToken();

  const createdAt = new Date();
  const expiresAt = new Date(createdAt);
  expiresAt.setSeconds(expiresAt.getSeconds() + 10);

  const insertResult = await db
    .insert(sessions)
    .values({
      id: sessionId,
      userId: userId,
      accessToken: accessToken,
      refreshToken: refreshToken,
      expiresAt: expiresAt,
      createdAt: createdAt,
      lastActive: createdAt,
    })
    .execute();

  if (insertResult === undefined) {
    console.error("Unable to create session");
    return {
      status: "error",
      message: "Unable to create session",
    };
  }

  // Sign the session and store it in a cookie
  try {
    const sessionCookie = await signToken({
      id: sessionId,
      userId: userId,
      accessToken: accessToken,
      refreshToken: refreshToken,
      expiresAt: expiresAt,
    });

    // Create cookie
    cookies().set("session", sessionCookie, {
      expires: expiresAt,
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
    });

    console.log("Successfully created session");
    console.log(
      "Has cookie: ",
      cookies().get("session") !== undefined ? "true" : "false"
    );

    return {
      status: "success",
      message: "Successfully created session",
      session: sessionCookie,
    };
  } catch (error) {
    return {
      status: "error",
      message: "Unable to store local session",
    };
  }
}
