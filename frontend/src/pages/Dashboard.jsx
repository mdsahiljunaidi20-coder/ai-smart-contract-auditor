import { useNavigate } from "react-router-dom";

export default function Dashboard() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-slate-900 p-8 text-gray-200">
      <h1 className="text-3xl font-bold mb-6">Dashboard</h1>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h2 className="text-xl font-semibold mb-2">New Audit</h2>
          <p className="text-sm mb-4">Analyze a new smart contract</p>
          <button
            onClick={() => navigate("/new-audit")}
            className="bg-blue-600 px-4 py-2 rounded hover:bg-blue-500"
          >
            Start Audit
          </button>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h2 className="text-xl font-semibold mb-2">Security Engine</h2>
          <p className="text-sm">Rule-based + Slither + AI</p>
        </div>

        <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
          <h2 className="text-xl font-semibold mb-2">Status</h2>
          <p className="text-green-400">System Operational</p>
        </div>

      </div>
    </div>
  );
}
