import { useNavigate } from "react-router-dom";

export default function Dashboard() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <h1 className="text-3xl font-bold mb-6">AI Smart Contract Auditor</h1>

      <button
        onClick={() => navigate("/new-audit")}
        className="bg-blue-600 px-6 py-3 rounded hover:bg-blue-700"
      >
        ➕ New Audit
      </button>
    </div>
  );
}
