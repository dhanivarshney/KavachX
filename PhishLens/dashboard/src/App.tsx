import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Navbar from "./components/Navbar";
import Footer from "./components/Footer";
import Home from "./pages/Home";
import Smishing from "./pages/Smishing";
import TrustReport from "./pages/TrustpilotHub";
import Stats from "./pages/Stats";
import { ToastProvider } from "./components/Toast";

export default function App() {
  return (
    <BrowserRouter>
      <ToastProvider>
        <div className="min-h-screen flex flex-col bg-slate-50 text-slate-900 selection:bg-blue-600 selection:text-white antialiased font-sans">
          <Navbar />
          <main className="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 md:py-10">
            <Routes>
              {/* Primary Routes */}
              <Route path="/" element={<Home />} />
              <Route path="/smishing" element={<Smishing />} />
              <Route path="/trust-report" element={<TrustReport />} />
              <Route path="/analytics" element={<Stats />} />

              {/* Backward compatibility aliases */}
              <Route path="/trustpilot" element={<Navigate to="/trust-report" replace />} />
              <Route path="/stats" element={<Navigate to="/analytics" replace />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
          <Footer />
        </div>
      </ToastProvider>
    </BrowserRouter>
  );
}
