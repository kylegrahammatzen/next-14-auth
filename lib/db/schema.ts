import {
  pgTable,
  text,
  boolean,
  integer,
  timestamp,
  uuid,
} from "drizzle-orm/pg-core";

export const users = pgTable("user", {
  id: uuid("id").notNull().primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull(),
  emailVerified: timestamp("emailVerified", { mode: "date" }),
  password: text("password").notNull(),
  createdAt: timestamp("createdAt", { mode: "date" }).notNull(),
  lastPasswordChange: timestamp("lastPasswordChange", { mode: "date" }),
});

export const sessions = pgTable("session", {
  id: uuid("id").notNull().primaryKey(),
  userId: uuid("userId")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  accessToken: text("accessToken").notNull(),
  refreshToken: text("refreshToken").notNull(),
  expiresAt: timestamp("expiresAt", { mode: "date" }).notNull(),
  createdAt: timestamp("createdAt", { mode: "date" }).notNull(),
  lastActive: timestamp("lastActive", { mode: "date" }).notNull(),
});

export const verifications = pgTable("verification", {
  userId: uuid("userId")
    .notNull()
    .primaryKey()
    .references(() => users.id, { onDelete: "cascade" }),
  code: integer("code").notNull(),
  expiresAt: timestamp("expiresAt", { mode: "date" }).notNull(),
});

export const passwordResets = pgTable("passwordReset", {
  id: uuid("id").notNull().primaryKey(),
  userId: uuid("userId")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  token: text("token").notNull(),
  createdAt: timestamp("createdAt", { mode: "date" }).notNull(),
  expiresAt: timestamp("expiresAt", { mode: "date" }).notNull(),
  used: boolean("used").notNull().default(false),
});
