<button
  onClick={() => {
    localStorage.removeItem("token");
    window.location.href = "/login";
  }}
  className="bg-red-600 px-4 py-1 rounded"
>
  Logout
</button>
