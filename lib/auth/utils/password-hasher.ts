"use server";

const bcrypt = require("bcrypt");

const saltRounds = 12;

export async function hashPassword(password: string) {
  try {
    return await bcrypt.hash(password, saltRounds);
  } catch (err) {
    console.error("Error hashing password:", err);
    throw err; // Rethrow the error for handling upstream
  }
}

export async function comparePassword(password: string, hash: string) {
  try {
    return await bcrypt.compare(password, hash);
  } catch (err) {
    console.error("Error comparing password:", err);
    throw err; // Rethrow the error for handling upstream
  }
}
