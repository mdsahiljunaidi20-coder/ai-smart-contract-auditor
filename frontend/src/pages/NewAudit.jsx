import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { analyzeContract } from "../services/api";

export default function NewAudit() {
  const [contractName, setContractName] = useState("");
  const [code, setCode] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleAnalyze = async () => {
    if (!contractName || !code) {
      alert("Please enter contract name and code");
      return;
    }

    try {
      setLoading(true);
      const report = await analyzeContract(contractName, code);

      // ✅ SAVE REPORT
      localStorage.setItem("audit_report", JSON.stringify(report));

      // ✅ GO TO RESULTS
      navigate("/results");
    } catch (err) {
      alert(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black text-white p-8">
      <h1 className="text-2xl font-bold mb-4">New Smart Contract Audit</h1>

      <input
        className="w-full p-2 mb-4 bg-gray-800 text-white rounded"
        placeholder="Contract Name (e.g. Wallet.sol)"
        value={contractName}
        onChange={(e) => setContractName(e.target.value)}
      />

      <textarea
        className="w-full h-64 p-2 mb-4 bg-gray-800 text-white rounded"
        placeholder="Paste Solidity code here"
        value={code}
        onChange={(e) => setCode(e.target.value)}
      />

      <button
        onClick={handleAnalyze}
        disabled={loading}
        className="bg-green-600 px-6 py-2 rounded hover:bg-green-700"
      >
        {loading ? "Analyzing..." : "Analyze"}
      </button>
    </div>
  );
}
