function Signup() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 text-white">
      <div className="w-96 p-6 bg-gray-800 rounded-lg">
        <h2 className="text-2xl font-bold mb-4 text-center">Signup</h2>

        <input
          type="text"
          placeholder="Username"
          className="w-full p-2 mb-3 rounded bg-gray-700"
        />

        <input
          type="password"
          placeholder="Password"
          className="w-full p-2 mb-4 rounded bg-gray-700"
        />

        <button className="w-full bg-green-600 hover:bg-green-700 p-2 rounded">
          Signup
        </button>
      </div>
    </div>
  );
}

export default Signup;
