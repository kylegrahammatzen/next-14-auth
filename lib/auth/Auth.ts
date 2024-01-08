import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";

const AUTH_KEY = process.env.AUTH_KEY;

/**
 * The configuration for the Auth class.
 */
export type AuthConfig = {
  publicRoutes?: string[];
  privateRoutes?: string[];
  redirectToLoginURL: string;
};

/**
 * Creates a new instance of the Auth class.
 * @param config The configuration for the middleware.
 * @returns A new instance of the Auth class.
 */
export function auth(config: AuthConfig) {
  return new Auth(config);
}

/**
 * Middleware that checks if the user is authenticated.
 */
class Auth {
  private readonly publicRoutes: string[];
  private readonly privateRoutes: string[];
  private readonly redirectToLoginURL: string;

  /**
   * Creates a new instance of the Auth class.
   * @param config The configuration for the middleware.
   */
  constructor(config: AuthConfig) {
    this.publicRoutes = config.publicRoutes ?? [];
    this.privateRoutes = config.privateRoutes ?? [];
    this.redirectToLoginURL = config.redirectToLoginURL;
  }

  /**
   * Middleware function that checks if the user is authenticated.
   * @param request The incoming request.
   * @returns A NextResponse if the user is not authenticated, otherwise void.
   */
  async middleware(request: NextRequest): Promise<NextResponse | void> {
    // console.log(
    //   `Received ${request.method} request to ${request.url} at ${new Date()}`
    // );

    const pathName = request.nextUrl.pathname;
    const publicRoute = this.isPublicRoute(pathName);
    const privateRoute = this.isPrivateRoute(pathName);

    // Check if the route is public and not private
    if (publicRoute && !privateRoute) {
      return NextResponse.next();
    }

    // Check if the user is authenticated
    if (privateRoute) {
      const sessionCookie = cookies().get("session");
      console.log("Session cookie pre-auth" + sessionCookie);
      const authenticated = await this.isAuthenticated(request);

      if (!authenticated) {
        return NextResponse.redirect(
          new URL(
            this.redirectToLoginURL + "?redirect_uri=" + request.nextUrl,
            request.url
          )
        );
      }
    }

    return NextResponse.next();
  }

  /**
   * Checks if the route is public.
   * @param url The URL to check.
   * @returns True if the route is public, otherwise false.
   */
  private isPublicRoute(url: string): boolean {
    return this.publicRoutes.some(
      (route) => url === route || url.startsWith(`${route}`)
    );
  }

  /**
   * Checks if the route is private.
   * @param url The URL to check.
   * @returns True if the route is private, otherwise false.
   */
  private isPrivateRoute(url: string): boolean {
    return this.privateRoutes.some(
      (route) => url === route || url.startsWith(`${route}`)
    );
  }

  /**
   * Checks if the user is authenticated.
   * @param request The incoming request.
   * @returns True if the user is authenticated, otherwise false.
   */
  private async isAuthenticated(request: NextRequest): Promise<boolean> {
    const sessionCookie = request.headers.get("Cookie");

    if (!sessionCookie) {
      console.log("No session cookie found");
      return false;
    }

    const getSession = async (url: string, method: "GET" | "POST" | "PUT") => {
      const response = await fetch(url, {
        method: method, // use the method parameter here
        headers: {
          "Content-Type": "application/json",
          "X-Auth-Key": String(AUTH_KEY),
          Cookie: sessionCookie,
        },
      });
      return response.json();
    };

    let session = await getSession(
      "http://localhost:3000/api/auth/session",
      "GET"
    );

    console.log(session);

    // Check if the session is expired and fetch a new one
    if (session.status === "expired") {
      console.log("Session expired, fetching new session...");
      session = await getSession(
        "http://localhost:3000/api/auth/session/refresh",
        "PUT"
      );
    }

    return session.status === "success";
  }
}
