import { useLocation } from "react-router-dom";

export default function Results() {
  const { state } = useLocation();

  if (!state) return <p>No results</p>;

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <h2 className="text-2xl mb-4">Audit Results</h2>

      {state.issues.map((issue, i) => (
        <div key={i} className="bg-gray-800 p-4 mb-4 rounded">
          <p><b>Check:</b> {issue.check}</p>
          <p><b>Impact:</b> {issue.impact}</p>
          <p><b>Why:</b> {issue.ai_explanation?.why}</p>
          <p className="text-green-400 mt-2">
            <b>Fix:</b> {issue.ai_fix?.note}
          </p>
        </div>
      ))}
    </div>
  );
}
