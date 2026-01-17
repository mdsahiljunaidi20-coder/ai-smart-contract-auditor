import { useState } from "react";
import { analyzeContract } from "../services/api";
import { useNavigate } from "react-router-dom";

export default function NewAudit() {
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  async function handleAnalyze() {
    if (!code.trim()) return alert("Paste contract code");

    try {
      setLoading(true);
      const result = await analyzeContract("TestContract", code);
      localStorage.setItem("lastReport", JSON.stringify(result));
      navigate("/results");
    } catch (e) {
      alert("Analysis failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      <h1 className="text-2xl font-bold mb-4">🧪 New Audit</h1>

      <textarea
        className="w-full h-64 p-3 bg-gray-800 rounded text-sm"
        placeholder="Paste Solidity contract here..."
        value={code}
        onChange={(e) => setCode(e.target.value)}
      />

      <button
        onClick={handleAnalyze}
        disabled={loading}
        className="mt-4 bg-green-600 px-4 py-2 rounded hover:bg-green-700"
      >
        {loading ? "Analyzing..." : "Analyze"}
      </button>
    </div>
  );
}
