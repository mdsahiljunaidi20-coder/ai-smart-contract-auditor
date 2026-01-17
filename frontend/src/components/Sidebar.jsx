export default function Sidebar() {
  return (
    <aside className="w-64 bg-white shadow-md min-h-screen p-4">
      <ul className="space-y-4">
        <li className="font-semibold text-gray-700">Dashboard</li>
        <li className="text-gray-600">New Audit</li>
        <li className="text-gray-600">History</li>
        <li className="text-gray-600">Profile</li>
      </ul>
    </aside>
  );
}
