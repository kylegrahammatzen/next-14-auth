"use server";

import { defaultLoginRedirect, defaultLogoutRedirect } from "@/middleware";
import { redirect } from "next/navigation";
import { cookies } from "next/headers";
import { db } from "@/lib/db";
import { users, verifications } from "@/lib/db/schema";
import { desc, eq } from "drizzle-orm";
import { comparePassword, hashPassword } from "../utils/PasswordHasher";
import { v4 as uuidv4 } from "uuid";
import { Resend } from "resend";
import { parse } from "path";
import { createSession } from "./SessionManager";

const resend = new Resend(process.env.RESEND_API_KEY);
const AUTH_KEY = process.env.AUTH_KEY;

/**
 * Registers a new user.
 * @param {string} name - User's name.
 * @param {string} email - User's email.
 * @param {string} password - User's password.
 */
export async function registerUser(
  name: string,
  email: string,
  password: string,
  confirmPassword: string
) {
  // Check if the password has at least 8 characters
  if (password.length < 8) {
    return {
      status: "error",
      message: "Password must be at least 8 characters long",
    };
  }

  // Check if the password has at least one uppercase character
  if (!/[A-Z]/.test(password)) {
    return {
      status: "error",
      message: "Password must have at least one uppercase character",
    };
  }

  // Check if the password has at least one number
  if (!/[0-9]/.test(password)) {
    return {
      status: "error",
      message: "Password must have at least one number",
    };
  }

  // Check if the passwords match
  if (password !== confirmPassword) {
    return {
      status: "error",
      message: "Passwords do not match",
    };
  }

  try {
    // Check if the email is already registered
    const result = await db.select().from(users).where(eq(users.email, email));

    if (result.length > 0) {
      return {
        status: "error",
        message: "Email already registered",
      };
    }

    // Create a new user
    const userId = uuidv4();
    const code = Math.floor(10000 + Math.random() * 90000);

    const accountTransaction = db.transaction(async (tx) => {
      await tx.insert(users).values({
        id: userId,
        name: name,
        email: email,
        password: await hashPassword(password),
        createdAt: new Date(),
      });
      await tx.insert(verifications).values({
        userId: userId,
        code: code,
        expiresAt: new Date(Date.now() + 1000 * 60 * 60),
      });
    });

    if (accountTransaction === undefined) {
      return {
        status: "error",
        message: "Unable to register account",
      };
    }

    console.log("User " + userId + " registered");

    // Send verification email
    try {
      const data = await resend.emails.send({
        from: "Bans <no-reply@bans.io>",
        to: email,
        subject: "[Bans.io] Verify your account",
        html: "Verification code: " + code,
      });

      // If the email failed to send, return an error
      if (data.error !== null) {
        console.error(data.error);
        return {
          status: "error",
          message: "Unable to send verification email",
        };
      }

      // If the email was sent successfully, return a success message
      console.log("Verification email sent to " + email);

      return {
        status: "success",
        userId: userId,
        message: "Verification email sent",
      };
    } catch (error) {
      console.error(error);
      return {
        status: "error",
        message: "Unable to send verification email",
      };
    }
  } catch (error) {
    return {
      status: "error",
      message: "Unable to login to account",
    };
  }
}

/**
 * Authenticates a user.
 * @param {string} email - User's email.
 * @param {string} password - User's password.
 */
export async function authenticateUser(email: string, password: string) {
  // Check if the password has at least 8 characters
  if (password.length < 8) {
    return {
      status: "error",
      message: "Password must be at least 8 characters long",
    };
  }

  // Check if the password has at least one uppercase character
  if (!/[A-Z]/.test(password)) {
    return {
      status: "error",
      message: "Password must have at least one uppercase character",
    };
  }

  // Check if the password has at least one number
  if (!/[0-9]/.test(password)) {
    return {
      status: "error",
      message: "Password must have at least one number",
    };
  }

  try {
    const result = await db.select().from(users).where(eq(users.email, email));

    if (result.length === 0) {
      return {
        status: "error",
        message: "Email was not found",
      };
    }

    const user = result[0];

    if (!(await comparePassword(password, user.password))) {
      return {
        status: "error",
        message: "Incorrect password",
      };
    }

    if (!user.emailVerified) {
      return {
        status: "unverified",
        userId: user.id,
      };
    }

    const session = await createSession(user.id);

    if (session.status === "error") {
      return {
        status: "error",
        message: "Unable to create session",
      };
    }

    return {
      status: "success",
      message: "Logged in successfully",
    };
  } catch (error) {
    console.error(error);
    return {
      status: "error",
      message: "Unable to login to account",
    };
  }
}

/**
 * Logs out the current user.
 */
export async function logoutUser() {
  // Get cookie store from request
  const cookieStore = cookies();

  // Get the session cookie from the request
  const sessionCookie = cookieStore.get("session");

  if (!sessionCookie) {
    return redirect(defaultLogoutRedirect);
  }

  // Delete the session cookie
  cookieStore.set("session", "", {
    maxAge: 0,
    path: "/",
  });

  return redirect(defaultLogoutRedirect);
}

/**
 * Verifies a user's email.
 * @param {string} id - User's ID.
 * @param {number[]} authCode - Authentication code, an array of 5 digits.
 */
export async function verifyUserEmail(userId: string, authCode: number[]) {
  try {
    // Check if the user exists
    const result = await db.select().from(users).where(eq(users.id, userId));

    if (result.length === 0) {
      return {
        status: "error",
        message: "User not found",
      };
    }

    const user = result[0];

    // Check if the user's email is already verified
    if (user.emailVerified) {
      return {
        status: "error",
        message: "Email already verified",
      };
    }

    // Retrieve user's latest verification code from the database
    const verificationResult = await db
      .select()
      .from(verifications)
      .where(eq(verifications.userId, userId))
      .orderBy(desc(verifications.expiresAt))
      .limit(1)
      .execute();

    if (verificationResult.length === 0) {
      return {
        status: "error",
        message: "Verification code not found",
      };
    }

    const verification = verificationResult[0];

    // Check if the verification is expired
    if (verification.expiresAt < new Date()) {
      return {
        status: "error",
        message: "Verification code has expired",
      };
    }

    // Check if the verification code matches
    if (verification.code !== parseInt(authCode.join(""))) {
      return {
        status: "error",
        message: "Incorrect verification code",
      };
    }

    const updateResult = await db
      .update(users)
      .set({
        emailVerified: new Date(),
      })
      .where(eq(users.id, userId))
      .execute();

    if (updateResult === undefined) {
      return {
        status: "error",
        message: "Unable to verify email",
      };
    }

    const session = await createSession(user.id);

    if (session.status === "error") {
      return {
        status: "error",
        message: "Unable to create session",
      };
    }

    return redirect(defaultLoginRedirect);
  } catch (error) {
    return {
      status: "error",
      message: "Unable to verify email",
    };
  }
}

export async function resendUserEmailVerification(userId: string) {
  // Check if the user exists
  const result = await db.select().from(users).where(eq(users.id, userId));

  if (result.length === 0) {
    return {
      status: "error",
      message: "User not found",
    };
  }

  const user = result[0];

  // Check if the user's email is already verified
  if (user.emailVerified) {
    return {
      status: "error",
      message: "Email already verified",
    };
  }

  // Retrieve user's latest verification code from the database
  const verificationResult = await db
    .select()
    .from(verifications)
    .where(eq(verifications.userId, userId))
    .orderBy(desc(verifications.expiresAt))
    .limit(1)
    .execute();

  const verification = verificationResult[0];

  if (verification !== undefined) {
    // Check if the last verification code was sent less than 5 minutes ago
    if (verification.expiresAt > new Date(Date.now() + 1000 * 60 * 5)) {
      return {
        status: "error",
        message:
          "Please wait a bit longer! You've already received a verification code less than 5 minutes ago.",
      };
    }
  }

  // Create a new verification code
  const code = Math.floor(10000 + Math.random() * 90000);

  // Make a new verification code
  const updateResult = await db
    .update(verifications)
    .set({
      code: code,
      expiresAt: new Date(Date.now() + 1000 * 60 * 60),
    })
    .where(eq(verifications.userId, userId))
    .execute();

  if (updateResult === undefined) {
    return {
      status: "error",
      message: "Unable to send verification email",
    };
  }

  // Send verification email
  try {
    const data = await resend.emails.send({
      from: "Bans <no-reply@bans.io>",
      to: user.email,
      subject: "[Bans.io] Verify your account",
      html: "Verification code: " + code,
    });

    // If the email failed to send, return an error
    if (data.error !== null) {
      console.error(data.error);
      return {
        status: "error",
        message: "Unable to send verification email",
      };
    }

    return {
      status: "success",
      message: "Verification email sent",
    };
  } catch (error) {
    console.error(error);
    return {
      status: "error",
      message: "Unable to send verification email",
    };
  }
}

/**
 * Resets the password of a user.
 * @param {string} email - User's email.
 * @param {string} token - Token received in the URL for password reset.
 */
export async function resetUserPassword(email: string, token: string) {}

// async function initializeSession(userId: string) {
//   // Create a new session
//   const createSession = async () => {
//     try {
//       const response = await fetch("https://localhost:3000/api/auth/session", {
//         method: "POST",
//         headers: {
//           "Content-Type": "application/json",
//           "X-Auth-Key": String(AUTH_KEY),
//           "X-Auth-User": String(userId),
//         },
//       });
//       return response.json();
//     } catch (error) {
//       // Log any error that occurs during the fetch or the conversion to json
//       console.error("Failed to create session:", error);
//       throw error; // rethrow the error so you can handle it in the calling function
//     }
//   };

//   console.log("Creating session");

//   try {
//     const session = await createSession();

//     if (session.status === "error") {
//       return {
//         status: "error",
//         message: "Unable to create session",
//       };
//     }

//     return {
//       status: "success",
//       message: "Logged in successfully",
//     };
//   } catch (error) {
//     // Handle or log error related to session creation
//     console.error("Error during session initialization:", error);
//     return {
//       status: "error",
//       message: "Unknown error occurred",
//     };
//   }
// }
