import { initializeAuthbase } from "@/lib/auth/authbase";
import { NextRequest } from "next/server";

// Default redirection URLs for authentication
const DEFAULT_LOGIN_REDIRECT_URL = "/dashboard";
const DEFAULT_LOGOUT_REDIRECT_URL = "/auth/login";

// Configuration for Authbase
const authbase = initializeAuthbase({
  publicEndpoints: ["/", "/auth/"],
  privateEndpoints: ["/dashboard"],
  loginRedirectURL: DEFAULT_LOGOUT_REDIRECT_URL,
});

/**
 * Middleware for handling authentication in Next.js.
 * @param {NextRequest} request - The incoming HTTP request.
 * @returns {Promise<NextResponse>} - The response from the middleware.
 */
export async function middleware(request: NextRequest) {
  // Processing the request through Authbase middleware
  return await authbase.handleRequest(request);
}

// Next.js routing configuration for excluding specific routes
// Learn more: https://nextjs.org/docs/app/building-your-application/routing/middleware
export const config = {
  matcher: ["/((?!.+\\.[\\w]+$|_next).*)", "/", "/(api|trpc)(.*)"],
};
