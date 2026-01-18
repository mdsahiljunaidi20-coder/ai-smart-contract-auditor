const API_BASE = "http://127.0.0.1:8000";

/* =========================
   AUTH – SIGNUP
========================= */
export async function signup(username, password) {
  const res = await fetch(`${API_BASE}/auth/signup`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, password }),
  });

  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Signup failed");
  }

  return res.json();
}

/* =========================
   AUTH – LOGIN
========================= */
export async function login(username, password) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, password }),
  });

  if (!res.ok) {
    throw new Error("Invalid username or password");
  }

  return res.json(); // { access_token, token_type }
}

/* =========================
   ANALYZE CONTRACT
========================= */
export async function analyzeContract(contract_name, code) {
  const token = localStorage.getItem("token");

  if (!token) {
    throw new Error("Not authenticated");
  }

  const res = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      contract_name,
      code,
    }),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(err || "Analysis failed");
  }

  return res.json();
}
