export default function Results() {
  const report = JSON.parse(localStorage.getItem("audit_report"));

  if (!report) {
    return (
      <div className="min-h-screen bg-black text-white flex items-center justify-center">
        No report found. Run an audit first.
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black text-white p-8">
      <h1 className="text-3xl font-bold mb-4">Audit Results</h1>

      <p className="mb-4 text-gray-400">
        Contract: <b>{report.contract}</b>
      </p>

      {report.issues.map((issue, idx) => (
        <div
          key={idx}
          className="bg-gray-900 p-4 rounded mb-4 border border-gray-700"
        >
          <h2 className="text-lg font-semibold text-yellow-400">
            {issue.check}
          </h2>

          <p>Impact: {issue.impact}</p>
          <p className="mt-2 text-gray-300">{issue.description}</p>

          {issue.ai_explanation && (
            <p className="mt-2 text-blue-400">
              Why: {issue.ai_explanation.why}
            </p>
          )}

          {issue.ai_fix && (
            <p className="mt-2 text-green-400">
              Fix: {issue.ai_fix.note}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}
