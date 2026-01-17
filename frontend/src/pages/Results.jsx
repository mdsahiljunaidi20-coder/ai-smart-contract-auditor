export default function Results() {
  const report = JSON.parse(localStorage.getItem("lastReport"));

  if (!report) {
    return <p className="text-white p-6">No report found</p>;
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      <h1 className="text-2xl font-bold mb-4">📄 Audit Results</h1>

      <p className="mb-2">Contract: {report.contract}</p>
      <p className="mb-4">Total Issues: {report.total_issues}</p>

      <pre className="bg-gray-800 p-4 rounded text-sm overflow-x-auto">
        {JSON.stringify(report.issues, null, 2)}
      </pre>
    </div>
  );
}
