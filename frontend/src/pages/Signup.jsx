import { useState } from "react";
import { signup } from "../services/api";
import { useNavigate } from "react-router-dom";

export default function Signup() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const navigate = useNavigate();

  const handleSignup = async (e) => {
    e.preventDefault();
    setError("");

    try {
      await signup(username, password);
      alert("Signup successful. Please login.");
      navigate("/login");
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="min-h-screen bg-black text-white flex items-center justify-center">
      <form
        onSubmit={handleSignup}
        className="bg-gray-900 p-6 rounded w-96"
      >
        <h2 className="text-xl mb-4 text-center">Sign Up</h2>

        {error && <p className="text-red-500 mb-2">{error}</p>}

        <input
          className="w-full p-2 mb-3 bg-gray-800 rounded"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />

        <input
          type="password"
          className="w-full p-2 mb-4 bg-gray-800 rounded"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />

        <button className="w-full bg-blue-600 p-2 rounded">
          Create Account
        </button>
      </form>
    </div>
  );
}
