import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { analyzeContract } from "../services/api";

export default function NewAudit() {
  const [name, setName] = useState("");
  const [code, setCode] = useState("");
  const navigate = useNavigate();

  const analyze = async () => {
    try {
      const result = await analyzeContract(name, code);
      navigate("/results", { state: result });
    } catch (err) {
      alert("Analysis failed. Check console.");
      console.error(err);
    }
  };

  return (
    <div className="p-6 text-white">
      <h2 className="text-2xl mb-4">New Audit</h2>

      <input
        className="w-full p-2 mb-3 text-black"
        placeholder="Contract name"
        value={name}
        onChange={(e) => setName(e.target.value)}
      />

      <textarea
        className="w-full h-64 p-2 text-black"
        placeholder="Paste Solidity code here"
        value={code}
        onChange={(e) => setCode(e.target.value)}
      />

      <button
        onClick={analyze}
        className="mt-4 px-4 py-2 bg-blue-600 rounded"
      >
        Analyze
      </button>
    </div>
  );
}
