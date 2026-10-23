import { useState, useEffect } from "react";
import {
  ShieldAlert,
  Link2,
  KeyRound,
  CreditCard,
  UserX,
  Smartphone,
  CheckCircle2,
  Circle,
  AlertTriangle,
  Phone,
  ExternalLink,
  XOctagon,
  ArrowLeft,
  Sparkles,
  ChevronRight,
  Shield,
  Clock,
  Download,
  Copy,
  Check,
  Building,
  Flame,
  FileText,
} from "lucide-react";
import {
  createIncident,
  toggleAction,
  closeIncident,
  getRecentScans,
  getIncidentDossierUrl,
} from "../api/phishlens";
import type { DamageControlIncident, ScanRecord } from "../api/phishlens";

const INCIDENT_TYPES = [
  {
    key: "clicked_link",
    label: "I clicked a suspicious link",
    description: "Opened an unfamiliar or alarming website in browser or chat",
    icon: Link2,
    color: "text-amber-600",
    bg: "bg-amber-50",
    border: "border-amber-200",
  },
  {
    key: "credentials_shared",
    label: "I shared my password or OTP",
    description: "Entered login credentials on a fake form or read an OTP to a caller",
    icon: KeyRound,
    color: "text-rose-600",
    bg: "bg-rose-50",
    border: "border-rose-200",
  },
  {
    key: "payment_sent",
    label: "I sent money to a scammer",
    description: "Transferred money via UPI, NetBanking, or entered card CVV/expiry",
    icon: CreditCard,
    color: "text-red-600",
    bg: "bg-red-50",
    border: "border-red-200",
  },
  {
    key: "sensitive_data_shared",
    label: "I shared personal identity records",
    description: "Disclosed Aadhaar, PAN card, date of birth, or confidential documents",
    icon: UserX,
    color: "text-orange-600",
    bg: "bg-orange-50",
    border: "border-orange-200",
  },
  {
    key: "suspicious_app",
    label: "I installed an unknown app or gave remote access",
    description: "Downloaded an APK file or installed AnyDesk / TeamViewer for KYC",
    icon: Smartphone,
    color: "text-purple-600",
    bg: "bg-purple-50",
    border: "border-purple-200",
  },
];

const BANK_OPTIONS = [
  "SBI",
  "HDFC",
  "ICICI",
  "Axis",
  "PNB",
  "Kotak",
  "Bank of Baroda",
  "PhonePe",
  "Google Pay",
  "Paytm",
  "Other Bank / Provider",
];

export default function DamageControl() {
  const [step, setStep] = useState<"select" | "questionnaire" | "recovery">("select");
  const [selectedType, setSelectedType] = useState<string>("clicked_link");
  const [loading, setLoading] = useState(false);
  const [incident, setIncident] = useState<DamageControlIncident | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [recentScans, setRecentScans] = useState<ScanRecord[]>([]);
  const [copiedDossier, setCopiedDossier] = useState(false);

  // Questionnaire form states
  const [url, setUrl] = useState("");
  const [actionTaken, setActionTaken] = useState("closed_page");
  const [accountType, setAccountType] = useState("banking");
  const [credentialType, setCredentialType] = useState("password_and_otp");
  const [passwordReused, setPasswordReused] = useState(false);
  const [paymentMethod, setPaymentMethod] = useState("upi");
  const [bankName, setBankName] = useState("SBI");
  const [amountLost, setAmountLost] = useState("");
  const [transactionId, setTransactionId] = useState("");
  const [timeElapsed, setTimeElapsed] = useState("under_2_hours");
  const [scammerContact, setScammerContact] = useState("");
  const [appType, setAppType] = useState("remote_desktop");
  const [devicePlatform, setDevicePlatform] = useState("android");
  const [personalDataItems, setPersonalDataItems] = useState<string[]>(["aadhaar"]);
  const [impersonationType, setImpersonationType] = useState("none");
  const [notes, setNotes] = useState("");

  // Load recent scans on mount for quick URL picking
  useEffect(() => {
    getRecentScans(10).then((scans) => setRecentScans(scans)).catch(() => {});
  }, []);

  function handleStartQuestionnaire(typeKey: string) {
    setSelectedType(typeKey);
    setStep("questionnaire");
    setError(null);
  }

  async function handleSubmitIncident() {
    setLoading(true);
    setError(null);

    const details: Record<string, any> = {
      time_elapsed: timeElapsed,
      notes: notes.trim(),
      scammer_contact: scammerContact.trim(),
    };

    if (selectedType === "clicked_link") {
      details.url = url.trim();
      details.action_taken = actionTaken;
    } else if (selectedType === "credentials_shared") {
      details.account_type = accountType;
      details.credential_type = credentialType;
      details.password_reused = passwordReused;
      if (accountType === "banking") {
        details.bank_name = bankName;
      }
    } else if (selectedType === "payment_sent") {
      details.payment_method = paymentMethod;
      details.bank_name = bankName;
      details.amount_lost = amountLost.trim();
      details.transaction_id = transactionId.trim();
    } else if (selectedType === "sensitive_data_shared") {
      details.personal_data_items = personalDataItems;
      details.impersonation_type = impersonationType;
    } else if (selectedType === "suspicious_app") {
      details.app_type = appType;
      details.device_platform = devicePlatform;
    }

    try {
      const result = await createIncident(selectedType, "dashboard", details);
      setIncident(result);
      setStep("recovery");
    } catch (err: any) {
      setError(err.message || "Failed to generate dynamic recovery plan. Please check backend status.");
    } finally {
      setLoading(false);
    }
  }

  async function handleToggleAction(actionId: string) {
    if (!incident) return;
    try {
      const updated = await toggleAction(incident.incident_id, actionId);
      setIncident(updated);
    } catch {
      // silently fail
    }
  }

  async function handleCloseIncident() {
    if (!incident) return;
    try {
      const updated = await closeIncident(incident.incident_id);
      setIncident(updated);
    } catch {
      // silently fail
    }
  }

  function handleCopyDossier() {
    if (!incident) return;
    fetch(getIncidentDossierUrl(incident.incident_id))
      .then((res) => res.text())
      .then((text) => {
        navigator.clipboard.writeText(text);
        setCopiedDossier(true);
        setTimeout(() => setCopiedDossier(false), 2500);
      })
      .catch(() => {});
  }

  function handleReset() {
    setStep("select");
    setIncident(null);
    setError(null);
    setUrl("");
    setAmountLost("");
    setTransactionId("");
    setScammerContact("");
    setNotes("");
  }

  function toggleDataItem(item: string) {
    if (personalDataItems.includes(item)) {
      setPersonalDataItems(personalDataItems.filter((i) => i !== item));
    } else {
      setPersonalDataItems([...personalDataItems, item]);
    }
  }

  const currentTypeMeta = INCIDENT_TYPES.find((t) => t.key === selectedType) || INCIDENT_TYPES[0];
  const progress = incident?.progress;

  return (
    <div className="space-y-6">
      {/* Hero Header */}
      <div className="relative rounded-3xl border border-slate-200 bg-white p-6 sm:p-8 overflow-hidden shadow-sm">
        <div className="absolute -top-24 -right-24 w-96 h-96 bg-rose-100/60 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 max-w-2xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-rose-50 border border-rose-200 text-[10px] font-semibold tracking-widest uppercase text-rose-600 mb-3">
            <ShieldAlert size={11} />
            <span>Interactive Incident Recovery System</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-slate-900 mb-2">
            Damage Control Center
          </h1>
          <p className="text-xs sm:text-sm text-slate-500 leading-relaxed">
            Victim of a scam, phishing lure, or unauthorized debit? Answer a few quick questions to receive
            an immediate, prioritized triage plan and generate a formal complaint dossier for law enforcement.
          </p>
        </div>
      </div>

      {error && (
        <div className="rounded-2xl bg-rose-50 border border-rose-200 p-4 text-xs text-rose-700 flex items-center gap-3">
          <AlertTriangle size={16} className="text-rose-500 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          STEP 1: Choose Scenario
      ────────────────────────────────────────────────────────────── */}
      {step === "select" && (
        <div className="space-y-4">
          <div className="flex items-center gap-2 px-1">
            <span className="text-xs font-semibold text-slate-800">Step 1 of 2: What happened?</span>
            <span className="text-[11px] text-slate-400">Select the situation that best matches your event</span>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            {INCIDENT_TYPES.map((type) => {
              const Icon = type.icon;
              return (
                <button
                  key={type.key}
                  onClick={() => handleStartQuestionnaire(type.key)}
                  className={`group relative flex items-start gap-4 p-5 rounded-2xl border ${type.border} ${type.bg} hover:shadow-md transition-all text-left cursor-pointer`}
                >
                  <div className={`p-2.5 rounded-xl ${type.bg} ${type.color} border ${type.border} shrink-0`}>
                    <Icon size={20} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <h3 className="text-sm font-bold text-slate-900 mb-0.5">{type.label}</h3>
                    <p className="text-xs text-slate-600 leading-relaxed">{type.description}</p>
                  </div>
                  <ChevronRight size={16} className="text-slate-400 group-hover:text-slate-600 mt-1 shrink-0 transition-colors" />
                </button>
              );
            })}
          </div>

          {/* Golden Hour Explanation Callout */}
          <div className="rounded-2xl border border-amber-200 bg-amber-50/70 p-4 flex items-start gap-3">
            <Clock size={18} className="text-amber-600 shrink-0 mt-0.5" />
            <div className="text-xs text-slate-700 leading-relaxed">
              <strong className="text-amber-800 block mb-0.5">The "Golden Hour" Protocol:</strong>
              If unauthorized money transfer or banking compromise took place within the last <strong>2 hours</strong>,
              reporting immediately to your bank and <strong>1930</strong> allows nodal officers to place an inter-bank
              hold on beneficiary accounts before scammers can cash out.
            </div>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          STEP 2: Dynamic Intake Questionnaire
      ────────────────────────────────────────────────────────────── */}
      {step === "questionnaire" && (
        <div className="rounded-3xl border border-slate-200 bg-white p-6 sm:p-8 space-y-6 shadow-sm">
          <div className="flex items-center justify-between pb-4 border-b border-slate-100">
            <button
              onClick={() => setStep("select")}
              className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-500 hover:text-slate-800 transition-colors cursor-pointer"
            >
              <ArrowLeft size={14} />
              <span>Change Scenario</span>
            </button>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-xl bg-slate-100 text-xs font-bold text-slate-800">
              <currentTypeMeta.icon size={14} className={currentTypeMeta.color} />
              <span>{currentTypeMeta.label}</span>
            </div>
          </div>

          <div className="space-y-5">
            {/* 1. Clicked Link Specifics */}
            {selectedType === "clicked_link" && (
              <>
                <div>
                  <label className="text-xs font-bold text-slate-700 block mb-1.5">
                    Website Address / Link You Clicked
                  </label>
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="e.g. https://paypa1-security-verification.com"
                    className="w-full text-xs font-mono bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  {recentScans.length > 0 && (
                    <div className="mt-2 flex flex-wrap items-center gap-1.5">
                      <span className="text-[10px] text-slate-400 font-semibold">Pick from Web Guard history:</span>
                      {recentScans.slice(0, 3).map((s) => (
                        <button
                          key={s.id}
                          type="button"
                          onClick={() => setUrl(s.url)}
                          className="text-[10px] font-mono px-2 py-0.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 truncate max-w-xs cursor-pointer"
                        >
                          {s.domain}
                        </button>
                      ))}
                    </div>
                  )}
                </div>

                <div>
                  <label className="text-xs font-bold text-slate-700 block mb-2">
                    What action took place on that page?
                  </label>
                  <div className="grid sm:grid-cols-3 gap-2.5 text-xs">
                    {[
                      { id: "closed_page", title: "Just opened & closed", desc: "Did not enter data or download" },
                      { id: "downloaded_file", title: "Downloaded a file", desc: "Saved an APK, ZIP, or EXE" },
                      { id: "entered_credentials", title: "Entered sensitive data", desc: "Typed password, OTP, or card info" },
                    ].map((opt) => (
                      <button
                        key={opt.id}
                        type="button"
                        onClick={() => setActionTaken(opt.id)}
                        className={`p-3.5 rounded-xl border text-left cursor-pointer transition-all ${
                          actionTaken === opt.id
                            ? "bg-blue-50 border-blue-400 text-blue-900 shadow-xs"
                            : "bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100"
                        }`}
                      >
                        <div className="font-bold">{opt.title}</div>
                        <div className="text-[11px] text-slate-500 mt-0.5">{opt.desc}</div>
                      </button>
                    ))}
                  </div>
                </div>
              </>
            )}

            {/* 2. Credentials Shared Specifics */}
            {selectedType === "credentials_shared" && (
              <>
                <div>
                  <label className="text-xs font-bold text-slate-700 block mb-2">
                    What kind of account was affected?
                  </label>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                    {[
                      { id: "banking", title: "NetBanking / UPI" },
                      { id: "email", title: "Google / Email" },
                      { id: "social", title: "WhatsApp / Social" },
                      { id: "work", title: "Office / Work ID" },
                    ].map((opt) => (
                      <button
                        key={opt.id}
                        type="button"
                        onClick={() => setAccountType(opt.id)}
                        className={`p-3 rounded-xl border text-center font-bold cursor-pointer transition-all ${
                          accountType === opt.id
                            ? "bg-blue-50 border-blue-400 text-blue-900"
                            : "bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100"
                        }`}
                      >
                        {opt.title}
                      </button>
                    ))}
                  </div>
                </div>

                {accountType === "banking" && (
                  <div>
                    <label className="text-xs font-bold text-slate-700 block mb-1.5">
                      Your Bank / Payment App
                    </label>
                    <select
                      value={bankName}
                      onChange={(e) => setBankName(e.target.value)}
                      className="w-full text-xs bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-900 font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      {BANK_OPTIONS.map((b) => (
                        <option key={b} value={b}>{b}</option>
                      ))}
                    </select>
                  </div>
                )}

                <div>
                  <label className="text-xs font-bold text-slate-700 block mb-2">
                    What information was disclosed?
                  </label>
                  <div className="grid sm:grid-cols-3 gap-2 text-xs">
                    {[
                      { id: "password_only", title: "Password Only" },
                      { id: "otp_only", title: "One-Time OTP Only" },
                      { id: "password_and_otp", title: "Both Password & OTP" },
                    ].map((opt) => (
                      <button
                        key={opt.id}
                        type="button"
                        onClick={() => setCredentialType(opt.id)}
                        className={`p-3 rounded-xl border text-center font-bold cursor-pointer transition-all ${
                          credentialType === opt.id
                            ? "bg-rose-50 border-rose-400 text-rose-900"
                            : "bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100"
                        }`}
                      >
                        {opt.title}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="flex items-center gap-3 p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                  <input
                    type="checkbox"
                    id="pwdReused"
                    checked={passwordReused}
                    onChange={(e) => setPasswordReused(e.target.checked)}
                    className="w-4 h-4 rounded text-blue-600 cursor-pointer"
                  />
                  <label htmlFor="pwdReused" className="text-xs text-slate-700 cursor-pointer font-medium">
                    I use this exact same password on other accounts (e.g. Gmail, personal banking).
                  </label>
                </div>
              </>
            )}

            {/* 3. Payment Sent Specifics */}
            {selectedType === "payment_sent" && (
              <>
                <div className="grid sm:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-bold text-slate-700 block mb-1.5">
                      Your Bank / Provider
                    </label>
                    <select
                      value={bankName}
                      onChange={(e) => setBankName(e.target.value)}
                      className="w-full text-xs bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-900 font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      {BANK_OPTIONS.map((b) => (
                        <option key={b} value={b}>{b}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="text-xs font-bold text-slate-700 block mb-1.5">
                      Payment Mode
                    </label>
                    <select
                      value={paymentMethod}
                      onChange={(e) => setPaymentMethod(e.target.value)}
                      className="w-full text-xs bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-900 font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="upi">UPI (PhonePe / GPay / Paytm)</option>
                      <option value="netbanking">NetBanking (IMPS / NEFT / RTGS)</option>
                      <option value="card">Debit / Credit Card</option>
                      <option value="crypto">Cryptocurrency / Gift Cards</option>
                    </select>
                  </div>
                </div>

                <div className="grid sm:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-bold text-slate-700 block mb-1.5">
                      Approximate Amount Transferred (₹)
                    </label>
                    <input
                      type="text"
                      value={amountLost}
                      onChange={(e) => setAmountLost(e.target.value)}
                      placeholder="e.g. 15,000"
                      className="w-full text-xs font-mono bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-bold text-slate-700 block mb-1.5">
                      Transaction ID / UTR (Optional)
                    </label>
                    <input
                      type="text"
                      value={transactionId}
                      onChange={(e) => setTransactionId(e.target.value)}
                      placeholder="e.g. 402918294012"
                      className="w-full text-xs font-mono bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-xs font-bold text-slate-700 block mb-1.5">
                    Scammer Contact / Beneficiary UPI ID (Optional)
                  </label>
                  <input
                    type="text"
                    value={scammerContact}
                    onChange={(e) => setScammerContact(e.target.value)}
                    placeholder="e.g. scammer@ybl or +91-9876543210"
                    className="w-full text-xs font-mono bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
              </>
            )}

            {/* 4. Sensitive Data Shared Specifics */}
            {selectedType === "sensitive_data_shared" && (
              <>
                <div>
                  <label className="text-xs font-bold text-slate-700 block mb-2">
                    Which credentials or documents were provided?
                  </label>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 text-xs">
                    {[
                      { id: "aadhaar", label: "Aadhaar Card / Number" },
                      { id: "pan", label: "PAN Card Details" },
                      { id: "card_cvv", label: "Debit / Credit Card & CVV" },
                      { id: "bank_acc", label: "Bank Account & IFSC" },
                      { id: "dob_mother", label: "Date of Birth / Mother's Name" },
                    ].map((item) => (
                      <button
                        key={item.id}
                        type="button"
                        onClick={() => toggleDataItem(item.id)}
                        className={`p-3 rounded-xl border text-left font-semibold cursor-pointer transition-all flex items-center justify-between ${
                          personalDataItems.includes(item.id)
                            ? "bg-orange-50 border-orange-400 text-orange-950"
                            : "bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100"
                        }`}
                      >
                        <span>{item.label}</span>
                        {personalDataItems.includes(item.id) && <Check size={14} className="text-orange-600" />}
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="text-xs font-bold text-slate-700 block mb-1.5">
                    Did the scammer impersonate an official organization?
                  </label>
                  <select
                    value={impersonationType}
                    onChange={(e) => setImpersonationType(e.target.value)}
                    className="w-full text-xs bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-900 font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="none">No official authority claimed</option>
                    <option value="police_digital_arrest">Police / CBI / Customs ("Digital Arrest" Scam)</option>
                    <option value="bank_manager">Bank Security / KYC Verification Officer</option>
                    <option value="electricity">Electricity / Utility Disconnection Dept</option>
                    <option value="courier">FedEx / India Post Suspended Package</option>
                  </select>
                </div>
              </>
            )}

            {/* 5. Suspicious App Specifics */}
            {selectedType === "suspicious_app" && (
              <>
                <div className="grid sm:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs font-bold text-slate-700 block mb-1.5">
                      What software was installed?
                    </label>
                    <select
                      value={appType}
                      onChange={(e) => setAppType(e.target.value)}
                      className="w-full text-xs bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-900 font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="remote_desktop">Remote Screen Tool (AnyDesk / TeamViewer / QuickSupport)</option>
                      <option value="apk">Sideloaded .apk file received on WhatsApp / Telegram</option>
                      <option value="banking_fake">Fake Banking / Rewards Application</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-xs font-bold text-slate-700 block mb-1.5">
                      Device Operating System
                    </label>
                    <select
                      value={devicePlatform}
                      onChange={(e) => setDevicePlatform(e.target.value)}
                      className="w-full text-xs bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-900 font-semibold focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                      <option value="android">Android Smartphone</option>
                      <option value="windows">Windows Laptop / PC</option>
                      <option value="ios">Apple iPhone (iOS)</option>
                      <option value="mac">MacBook / macOS</option>
                    </select>
                  </div>
                </div>
              </>
            )}

            {/* Common Time Elapsed Question */}
            <div>
              <label className="text-xs font-bold text-slate-700 block mb-2 flex items-center gap-1.5">
                <Clock size={13} className="text-slate-500" />
                <span>How much time has passed since this event?</span>
              </label>
              <div className="grid sm:grid-cols-3 gap-2 text-xs">
                {[
                  { id: "under_2_hours", label: "Under 2 Hours (Golden Hour)", desc: "Highest recovery rate" },
                  { id: "2_to_24_hours", label: "2 to 24 Hours", desc: "Report today" },
                  { id: "over_24_hours", label: "Over 24 Hours", desc: "Formal cyber complaint" },
                ].map((opt) => (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setTimeElapsed(opt.id)}
                    className={`p-3 rounded-xl border text-left cursor-pointer transition-all ${
                      timeElapsed === opt.id
                        ? "bg-blue-50 border-blue-500 text-blue-900 shadow-xs"
                        : "bg-slate-50 border-slate-200 text-slate-700 hover:bg-slate-100"
                    }`}
                  >
                    <div className="font-bold">{opt.label}</div>
                    <div className="text-[11px] text-slate-500 mt-0.5">{opt.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Additional Notes */}
            <div>
              <label className="text-xs font-bold text-slate-700 block mb-1.5">
                Additional Details / Notes (Optional)
              </label>
              <textarea
                rows={2}
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Describe any caller names, specific claims made, or unusual behavior observed..."
                className="w-full text-xs bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
          </div>

          <div className="pt-4 border-t border-slate-100 flex items-center justify-end">
            <button
              onClick={handleSubmitIncident}
              disabled={loading}
              className="inline-flex items-center gap-2 px-6 py-3 rounded-2xl bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs tracking-wide shadow-md shadow-blue-500/20 cursor-pointer disabled:opacity-50 transition-all"
            >
              <Sparkles size={14} />
              <span>{loading ? "Generating Dynamic Checklist..." : "Generate Action Plan"}</span>
            </button>
          </div>
        </div>
      )}

      {/* ─────────────────────────────────────────────────────────────
          STEP 3: Dynamic Recovery Plan & Dossier Hub
      ────────────────────────────────────────────────────────────── */}
      {step === "recovery" && incident && (
        <div className="space-y-6">
          {/* Top Actions Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <button
              onClick={handleReset}
              className="inline-flex items-center gap-2 text-xs font-semibold text-slate-600 hover:text-slate-900 transition-colors cursor-pointer"
            >
              <ArrowLeft size={14} />
              <span>Report New Incident</span>
            </button>

            <div className="flex items-center gap-2">
              <button
                onClick={handleCopyDossier}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold shadow-xs cursor-pointer"
              >
                {copiedDossier ? <Check size={13} className="text-emerald-600" /> : <Copy size={13} />}
                <span>{copiedDossier ? "Complaint Copied!" : "Copy Complaint Draft"}</span>
              </button>

              <a
                href={getIncidentDossierUrl(incident.incident_id)}
                download
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold shadow-xs transition-colors cursor-pointer"
              >
                <Download size={13} />
                <span>Download Cybercrime FIR Dossier (.txt)</span>
              </a>
            </div>
          </div>

          {/* Golden Hour Urgent Callout Banner */}
          {incident.golden_hour && (
            <div className="p-5 rounded-3xl border border-rose-300 bg-gradient-to-r from-rose-50 to-amber-50 shadow-sm flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-3 rounded-2xl bg-rose-500 text-white shrink-0 shadow-sm animate-pulse">
                  <Flame size={24} />
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-[10px] font-bold uppercase tracking-widest text-rose-700 bg-rose-100 px-2 py-0.5 rounded-md">
                      URGENT ACTION REQUIRED
                    </span>
                    <span className="text-xs font-bold text-rose-900">Golden Hour Protocol Active</span>
                  </div>
                  <p className="text-xs text-slate-700 leading-relaxed font-medium">
                    Funds or credentials were lost within the last 2 hours. Call <strong>1930</strong> and your bank fraud desk immediately to recall pending settlement batches!
                  </p>
                </div>
              </div>
              <a
                href="tel:1930"
                className="shrink-0 px-4 py-2.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-xs font-black shadow-sm flex items-center gap-2 cursor-pointer"
              >
                <Phone size={14} />
                <span>Dial 1930 Now</span>
              </a>
            </div>
          )}

          {/* Incident Status Banner */}
          <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">
                  Incident ID: {incident.incident_id}
                </span>
                <span
                  className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full border ${
                    incident.severity === "CRITICAL"
                      ? "bg-rose-50 text-rose-700 border-rose-200"
                      : incident.severity === "HIGH"
                      ? "bg-amber-50 text-amber-700 border-amber-200"
                      : "bg-blue-50 text-blue-700 border-blue-200"
                  }`}
                >
                  {incident.severity} SEVERITY
                </span>
                {incident.status === "resolved" && (
                  <span className="text-[10px] font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-full">
                    RESOLVED
                  </span>
                )}
              </div>
              <h2 className="text-lg font-black text-slate-900">{incident.incident_label}</h2>
              <p className="text-xs text-slate-600 leading-relaxed max-w-2xl font-medium">
                {incident.risk_summary}
              </p>
            </div>

            {progress && (
              <div className="flex items-center gap-3 shrink-0 self-end md:self-auto">
                <div className="text-right">
                  <span className="text-xs font-bold text-slate-800 block">
                    {progress.completed}/{progress.total} Tasks Completed
                  </span>
                  <span className="text-[10px] text-slate-400 font-mono">
                    {progress.percentage}% mitigated
                  </span>
                </div>
                <div className="w-24 h-2.5 rounded-full bg-slate-100 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      progress.percentage === 100 ? "bg-emerald-500" : "bg-blue-600"
                    }`}
                    style={{ width: `${progress.percentage}%` }}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Correlated Scan Highlight */}
          {incident.details?.correlated_scan && (
            <div className="rounded-3xl border border-blue-200 bg-blue-50/60 p-5 shadow-sm flex items-start gap-4">
              <div className="p-2.5 rounded-2xl bg-blue-100 text-blue-700 shrink-0">
                <Shield size={20} />
              </div>
              <div className="flex-1 min-w-0">
                <span className="text-[10px] font-mono uppercase tracking-wider text-blue-700 font-bold block mb-0.5">
                  KavachX Threat Telemetry Linked
                </span>
                <span className="text-xs font-mono font-bold text-slate-900 truncate block">
                  {incident.details.correlated_scan.url}
                </span>
                <div className="flex items-center gap-2 mt-1 text-xs">
                  <span className="font-bold text-rose-600 font-mono">
                    Risk Score: {incident.details.correlated_scan.risk_score}/100
                  </span>
                  <span className="text-slate-400">•</span>
                  <span className="text-slate-600 text-[11px]">
                    Flags: {incident.details.correlated_scan.reasons.join(", ") || "Anomalous structure"}
                  </span>
                </div>
              </div>
            </div>
          )}

          <div className="grid md:grid-cols-3 gap-6">
            {/* Left 2/3: Recovery Checklist Steps */}
            <div className="md:col-span-2 space-y-4">
              <h3 className="text-xs font-bold text-slate-700 uppercase tracking-wider flex items-center gap-2">
                <Shield size={14} className="text-blue-600" />
                <span>Tailored Mitigation Checklist (Click to Complete)</span>
              </h3>

              <div className="space-y-3">
                {incident.actions.map((action) => (
                  <button
                    key={action.id}
                    onClick={() => handleToggleAction(action.id)}
                    className={`w-full text-left flex items-start gap-3.5 p-4 rounded-2xl border transition-all cursor-pointer ${
                      action.completed
                        ? "bg-emerald-50/70 border-emerald-200"
                        : "bg-white border-slate-200 hover:border-blue-300 hover:shadow-sm"
                    }`}
                  >
                    <div className="mt-0.5 shrink-0">
                      {action.completed ? (
                        <CheckCircle2 size={20} className="text-emerald-600" />
                      ) : (
                        <Circle size={20} className="text-slate-300" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-bold text-slate-500 bg-slate-100 px-1.5 py-0.5 rounded">
                          Priority {action.priority}
                        </span>
                        {action.completed && (
                          <span className="text-[10px] font-semibold text-emerald-700">Completed</span>
                        )}
                      </div>
                      <h4
                        className={`text-sm font-semibold mt-1 ${
                          action.completed ? "text-emerald-800 line-through" : "text-slate-900"
                        }`}
                      >
                        {action.title}
                      </h4>
                      {action.detail && (
                        <p className="text-xs text-slate-600 leading-relaxed mt-1">{action.detail}</p>
                      )}
                    </div>
                  </button>
                ))}
              </div>

              {/* Mark Resolved Button */}
              {incident.status !== "resolved" && progress && progress.completed > 0 && (
                <button
                  onClick={handleCloseIncident}
                  className="w-full mt-4 py-3 rounded-2xl bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold transition-colors cursor-pointer shadow-sm"
                >
                  Mark All Steps Completed & Archive Incident
                </button>
              )}
            </div>

            {/* Right 1/3: Warnings & Helplines */}
            <div className="space-y-5">
              {/* Emergency Helplines */}
              <div className="rounded-3xl border border-blue-200 bg-blue-50/60 p-5 space-y-3">
                <h4 className="text-xs font-bold text-blue-800 uppercase tracking-wider flex items-center gap-1.5">
                  <Building size={14} />
                  <span>Immediate Emergency Helplines</span>
                </h4>
                <div className="space-y-2.5">
                  {incident.helplines.map((helpline, idx) => (
                    <div key={idx} className="p-3 rounded-xl bg-white border border-blue-100 shadow-xs">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold text-slate-900">{helpline.name}</span>
                        {helpline.url && (
                          <a
                            href={helpline.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-600 hover:text-blue-700"
                          >
                            <ExternalLink size={12} />
                          </a>
                        )}
                      </div>
                      <div className="text-sm font-black text-blue-700 mt-0.5">{helpline.contact}</div>
                      <p className="text-[10px] text-slate-500 mt-1 leading-relaxed">{helpline.note}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* What NOT To Do */}
              {incident.donts.length > 0 && (
                <div className="rounded-3xl border border-rose-200 bg-rose-50/70 p-5 space-y-3">
                  <h4 className="text-xs font-bold text-rose-800 uppercase tracking-wider flex items-center gap-1.5">
                    <XOctagon size={13} />
                    <span>What NOT To Do</span>
                  </h4>
                  <div className="space-y-2">
                    {incident.donts.map((dont, idx) => (
                      <div key={idx} className="flex items-start gap-2 text-xs text-rose-800">
                        <span className="text-rose-500 mt-0.5 shrink-0 font-bold">✕</span>
                        <span className="leading-relaxed">{dont}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Formal Dossier Generation Card */}
              <div className="rounded-3xl border border-slate-200 bg-white p-5 space-y-2 shadow-xs">
                <div className="flex items-center gap-2 text-xs font-bold text-slate-800">
                  <FileText size={14} className="text-blue-600" />
                  <span>FIR / Cybercrime Dossier</span>
                </div>
                <p className="text-[11px] text-slate-500 leading-relaxed">
                  KavachX has assembled a formal incident docket formatted with your statement,
                  UTR references, and scammer handles. You can submit this directly at your local police station or online.
                </p>
                <div className="pt-2">
                  <a
                    href={getIncidentDossierUrl(incident.incident_id)}
                    download
                    className="inline-flex items-center justify-center gap-1.5 w-full py-2.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-800 text-xs font-bold transition-colors cursor-pointer border border-slate-200"
                  >
                    <Download size={13} />
                    <span>Download Report (.txt)</span>
                  </a>
                </div>
              </div>

              {/* Disclaimer */}
              <div className="rounded-2xl bg-slate-50 border border-slate-200 p-4 text-[10px] text-slate-500 leading-relaxed">
                <strong className="text-slate-700">Disclaimer:</strong> {incident.disclaimer}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
