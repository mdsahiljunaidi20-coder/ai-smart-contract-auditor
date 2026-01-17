import { Link } from "react-router-dom";

export default function Landing() {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center text-center">
      <h1 className="text-4xl font-bold mb-4">
        AI Smart Contract Auditor
      </h1>
      <p className="text-gray-400 mb-6">
        Detect vulnerabilities. Get AI explanations. Improve security.
      </p>

      <div className="flex gap-4">
        <Link to="/login" className="px-4 py-2 bg-blue-600 rounded">
          Login
        </Link>
        <Link to="/signup" className="px-4 py-2 bg-gray-700 rounded">
          Signup
        </Link>
      </div>
    </div>
  );
}
