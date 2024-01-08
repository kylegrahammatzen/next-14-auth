import Link from "next/link";

export default function Page() {
  return (
    <div className="min-h-screen flex items-center">
      <div className="sm:mx-auto sm:w-full max-w-md">
        <h1 className="font-bold text-black">
          Next 14 Email Authentication Kit
        </h1>
        <p className="mt-4">
          With Next.js middleware, we can verify users before they access your
          app.
        </p>
        <p className="mt-4">
          User authentication tokens securely stored in the{" "}
          <span className="text-pink-500">session</span> cookie.
        </p>
        <p className="mt-4">
          Once authenticated, users can access the{" "}
          <Link
            href="/dashboard"
            className={
              "text-blue-600 hover:text-blue-500 transition duration-150 ease-in-out"
            }
          >
            /dashboard
          </Link>{" "}
          page.
        </p>
        <p className="mt-4">
          To gain access to protected content, users must register and verify
          their email.
        </p>

        <div className="mt-4">
          <Link
            href="/auth/register"
            className="flex justify-center rounded-md bg-blue-600 px-3 py-1.5 text-sm font-semibold leading-6 text-white shadow-sm hover:bg-blue-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600"
          >
            Register
          </Link>
        </div>
      </div>
    </div>
  );
}
