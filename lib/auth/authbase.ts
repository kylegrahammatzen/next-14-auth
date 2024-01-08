import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";

const AUTH_KEY = process.env.AUTH_KEY;

/**
 * Authbase configuration settings.
 */
export interface AuthbaseConfig {
  publicEndpoints?: string[];
  privateEndpoints?: string[];
  loginRedirectURL: string;
}

/**
 * Initializes Authbase with specified configuration.
 * @param config Configuration settings for Authbase.
 * @returns Instance of Authbase.
 */
export function initializeAuthbase(config: AuthbaseConfig) {
  return new Authbase(config);
}

/**
 * Authbase class for handling authentication.
 */
class Authbase {
  private readonly publicEndpoints: string[];
  private readonly privateEndpoints: string[];
  private readonly loginRedirectURL: string;

  constructor(config: AuthbaseConfig) {
    this.publicEndpoints = config.publicEndpoints ?? [];
    this.privateEndpoints = config.privateEndpoints ?? [];
    this.loginRedirectURL = config.loginRedirectURL;
  }

  /**
   * Middleware for authenticating requests.
   * @param request Incoming request object.
   * @returns NextResponse or void based on authentication status.
   */
  async handleRequest(request: NextRequest): Promise<NextResponse | void> {
    const path = request.nextUrl.pathname;
    const isPublicEndpoint = this.checkPublicEndpoint(path);
    const isPrivateEndpoint = this.checkPrivateEndpoint(path);

    if (isPublicEndpoint && !isPrivateEndpoint) {
      return NextResponse.next();
    }

    if (isPrivateEndpoint) {
      const sessionCookie = cookies().get("session");
      const isAuthenticated = await this.verifyAuthentication(request);

      if (!isAuthenticated) {
        return NextResponse.redirect(
          new URL(
            this.loginRedirectURL + "?redirect_uri=" + request.nextUrl,
            request.url
          )
        );
      }
    }

    return NextResponse.next();
  }

  private checkPublicEndpoint(url: string): boolean {
    return this.publicEndpoints.some(
      (route) => url === route || url.startsWith(route)
    );
  }

  private checkPrivateEndpoint(url: string): boolean {
    return this.privateEndpoints.some(
      (route) => url === route || url.startsWith(route)
    );
  }

  private async verifyAuthentication(request: NextRequest): Promise<boolean> {
    const sessionCookie = request.headers.get("Cookie");

    if (!sessionCookie) {
      return false;
    }

    const fetchSession = async (
      url: string,
      method: "GET" | "POST" | "PUT"
    ) => {
      const response = await fetch(url, {
        method,
        headers: {
          "Content-Type": "application/json",
          "X-Auth-Key": String(AUTH_KEY),
          Cookie: sessionCookie,
        },
      });
      return response.json();
    };

    let session = await fetchSession(
      "http://localhost:3000/api/authbase/session",
      "GET"
    );

    if (session.status === "expired") {
      session = await fetchSession(
        "http://localhost:3000/api/authbase/session/refresh",
        "PUT"
      );
    }

    return session.status === "success";
  }
}
