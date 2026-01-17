const API_BASE = "http://127.0.0.1:8000";

export async function analyzeContract(contract_name, code) {
  const token = localStorage.getItem("token");

  const res = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`,
    },
    body: JSON.stringify({ contract_name, code }),
  });

  if (!res.ok) {
    throw new Error("Analysis failed");
  }

  return res.json();
}
