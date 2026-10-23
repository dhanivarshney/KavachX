"""Damage-Control Mode – dynamic, contextual recovery engine."""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.services.recent_scans import RECENT_SCANS

DB_PATH = Path(__file__).resolve().parents[2] / "damage_control.db"

BANK_HELPLINES: dict[str, dict[str, str]] = {
    "SBI": {"phone": "1800-11-2211 / 1800-425-3800", "portal": "https://www.onlinesbi.sbi"},
    "HDFC": {"phone": "1800-202-6161", "portal": "https://netbanking.hdfcbank.com"},
    "ICICI": {"phone": "1800-1080", "portal": "https://www.icicibank.com"},
    "Axis": {"phone": "1860-419-5555", "portal": "https://www.axisbank.com"},
    "PNB": {"phone": "1800-180-2222", "portal": "https://netpnb.com"},
    "Kotak": {"phone": "1860-266-2666", "portal": "https://www.kotak.com"},
    "Bank of Baroda": {"phone": "1800-5700", "portal": "https://www.bankofbaroda.in"},
    "PhonePe": {"phone": "080-68727374 / 022-68727374", "portal": "https://support.phonepe.com"},
    "Google Pay": {"phone": "1800-419-0157", "portal": "https://support.google.com/pay/india"},
    "Paytm": {"phone": "0120-3888388", "portal": "https://paytm.com/care"},
}

INCIDENT_LABELS = {
    "clicked_link": "Clicked a Suspicious Link",
    "credentials_shared": "Shared Password or OTP",
    "payment_sent": "Sent Money to a Scammer",
    "sensitive_data_shared": "Shared Personal Information",
    "suspicious_app": "Installed a Suspicious App / Remote Access",
}


def _init_db() -> None:
    """Create the tables if they don't exist and ensure columns exist."""
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            incident_type TEXT NOT NULL,
            channel TEXT,
            details TEXT,
            severity TEXT NOT NULL DEFAULT 'HIGH',
            golden_hour INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'action_required',
            created_at TEXT NOT NULL,
            closed_at TEXT
        )
    """)
    # Check if severity and golden_hour exist on existing table
    c.execute("PRAGMA table_info(incidents)")
    existing_cols = [row[1] for row in c.fetchall()]
    if "severity" not in existing_cols:
        c.execute("ALTER TABLE incidents ADD COLUMN severity TEXT NOT NULL DEFAULT 'HIGH'")
    if "golden_hour" not in existing_cols:
        c.execute("ALTER TABLE incidents ADD COLUMN golden_hour INTEGER NOT NULL DEFAULT 0")

    c.execute("""
        CREATE TABLE IF NOT EXISTS incident_actions (
            id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            action_key TEXT NOT NULL,
            priority INTEGER NOT NULL,
            title TEXT NOT NULL,
            detail TEXT,
            completed INTEGER NOT NULL DEFAULT 0,
            completed_at TEXT,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)
    conn.commit()
    conn.close()


_init_db()


def _evaluate_plan_and_severity(
    incident_type: str, details: dict[str, Any]
) -> tuple[str, bool, str, list[dict[str, Any]], list[str], list[dict[str, str]]]:
    """Dynamically determine severity, risk summary, prioritized actions, and donts based on answers."""
    actions: list[dict[str, Any]] = []
    donts: list[str] = []
    severity = "HIGH"
    golden_hour = False
    risk_summary = ""

    time_elapsed = str(details.get("time_elapsed", "")).lower()
    is_under_2h = "under_2" in time_elapsed or "< 2" in time_elapsed or "just now" in time_elapsed
    bank_name = details.get("bank_name", "").strip()
    bank_info = BANK_HELPLINES.get(bank_name)

    # 1. Clicked Link
    if incident_type == "clicked_link":
        action_taken = details.get("action_taken", "closed_page")
        target_url = details.get("url", "").strip()

        if action_taken == "entered_credentials":
            severity = "CRITICAL"
            risk_summary = "High danger: You entered sensitive credentials on a suspicious website. Attackers can actively weaponize this access."
            actions.append({
                "key": "change_pwd_now",
                "priority": 1,
                "title": "Immediately change password for the entered account",
                "detail": "Use a clean device. Reset passwords immediately, and if you use this password anywhere else, change those as well.",
            })
            actions.append({
                "key": "revoke_sessions",
                "priority": 2,
                "title": "Revoke active sessions and log out other devices",
                "detail": "Visit account security settings and terminate all active sessions so the intruder is locked out.",
            })
            donts.append("Don't wait to reset passwords — automated credential stuffing takes seconds.")
        elif action_taken == "downloaded_file":
            severity = "HIGH"
            risk_summary = "Payload risk: A file was downloaded or execution permissions were granted. Potential malware, infostealer, or keylogger risk."
            actions.append({
                "key": "delete_downloads",
                "priority": 1,
                "title": "Delete downloaded files immediately without opening them",
                "detail": "Check your browser Downloads folder. Permanently delete any .exe, .apk, .zip, or .bat files downloaded from the suspicious link.",
            })
            actions.append({
                "key": "scan_antivirus",
                "priority": 2,
                "title": "Run a full device antivirus / malware scan",
                "detail": "Use Windows Defender / phone built-in security to inspect background processes.",
            })
            donts.append("Don't double-click or open any newly downloaded file from this site.")
        else:
            severity = "MODERATE"
            risk_summary = "Cautious alert: You opened the link but did not enter data or download files. Primary risk is browser-fingerprinting or phishing reconnaissance."
            actions.append({
                "key": "close_tabs",
                "priority": 1,
                "title": "Close the website tab and clear recent browser cache",
                "detail": "Close all related tabs. In your browser settings, clear recent cookies and cache for that site.",
            })
            actions.append({
                "key": "block_notifications",
                "priority": 2,
                "title": "Revoke website notification permissions",
                "detail": "Check browser settings > Site Settings > Notifications to ensure the rogue domain cannot spam you with fake alerts.",
            })
            donts.append("Don't re-open the link or click 'Allow' on any browser pop-ups.")

        actions.append({
            "key": "monitor_alerts",
            "priority": 3,
            "title": "Enable login alerts and watch for suspicious sign-ins",
            "detail": "Check your email/SMS for two-factor requests that you did not initiate.",
        })

    # 2. Credentials Shared
    elif incident_type == "credentials_shared":
        cred_type = details.get("credential_type", "password_only")
        account_type = details.get("account_type", "email")
        password_reused = details.get("password_reused", False)
        is_banking = account_type in ("banking", "upi", "netbanking")

        if is_banking or "otp" in str(cred_type).lower():
            severity = "CRITICAL"
            golden_hour = is_under_2h
            risk_summary = f"CRITICAL COMPROMISE: An OTP or financial password was provided. Threat actors may initiate unauthorized debits or take over your {account_type}."
        else:
            severity = "HIGH"
            risk_summary = f"Account integrity at risk: Credentials exposed for your {account_type} account."

        if is_banking:
            actions.append({
                "key": "freeze_netbanking",
                "priority": 1,
                "title": f"Contact {bank_name or 'your bank'} emergency fraud line immediately",
                "detail": f"Dial {bank_info['phone'] if bank_info else 'your bank toll-free fraud number'} right now to freeze netbanking and UPI access.",
            })

        actions.append({
            "key": "reset_primary_pwd",
            "priority": len(actions) + 1,
            "title": "Change the password immediately from a secure device",
            "detail": "Choose a strong, unique passphrase with at least 14 characters including numbers and symbols.",
        })

        if password_reused:
            actions.append({
                "key": "cross_service_reset",
                "priority": len(actions) + 1,
                "title": "⚠️ Password Reuse Detected: Reset other matching accounts",
                "detail": "Because you reported using this password elsewhere, immediately reset your main email and banking passwords.",
            })

        actions.append({
            "key": "enable_authenticator_2fa",
            "priority": len(actions) + 1,
            "title": "Upgrade to App-based Two-Factor Authentication (2FA)",
            "detail": "Switch away from SMS OTPs to Google Authenticator or Microsoft Authenticator, which cannot be intercepted by SIM swap.",
        })

        actions.append({
            "key": "audit_recovery_details",
            "priority": len(actions) + 1,
            "title": "Audit recovery email, backup phone, and trusted devices",
            "detail": "Verify that the scammer has not added their own backup email or phone number in account settings.",
        })

        donts.extend([
            "Don't share any subsequent OTPs with callers claiming to be 'cyber police' or 'bank security'.",
            "Don't reuse this password ever again.",
            "Don't keep active sessions alive on unfamiliar computers or phones.",
        ])

    # 3. Payment Sent
    elif incident_type == "payment_sent":
        severity = "CRITICAL"
        golden_hour = is_under_2h
        amount = details.get("amount_lost", "")
        tx_id = details.get("transaction_id", "")
        pay_method = details.get("payment_method", "upi")

        if is_under_2h:
            risk_summary = f"🚨 GOLDEN HOUR ACTIVE: Funds sent recently ({time_elapsed}). Inter-bank settlement holds and nodal freezes can recover money if reported within 2 hours!"
        else:
            risk_summary = f"Financial Fraud Reported: Total amount approx {amount or 'unspecified'} sent via {pay_method.upper()}. Immediate registration is mandatory for legal claim."

        actions.append({
            "key": "call_1930_first",
            "priority": 1,
            "title": "Dial National Cyber Crime Helpline '1930' immediately",
            "detail": "State the transaction details, your bank, victim account, and beneficiary account/UPI ID to trigger the inter-bank freeze protocol.",
        })

        if bank_info:
            actions.append({
                "key": "call_bank_fraud_desk",
                "priority": 2,
                "title": f"Call {bank_name} Emergency Fraud Desk at {bank_info['phone']}",
                "detail": f"Request a dispute chargeback / recall for Transaction ID: {tx_id or 'the recent transaction'}. Ask for an Incident Complaint Reference number.",
            })
        else:
            actions.append({
                "key": "call_bank_fraud_desk",
                "priority": 2,
                "title": "Call your bank's 24/7 emergency debit/fraud card helpline",
                "detail": "Inform the operator that the transaction was fraudulent and ask for a nodal account freeze.",
            })

        actions.append({
            "key": "file_formal_cybercrime_complaint",
            "priority": 3,
            "title": "Submit detailed complaint on cybercrime.gov.in within 24 hours",
            "detail": "Upload payment screenshots, SMS debit notifications, and fraudster contact details. Download the acknowledgment slip.",
        })

        actions.append({
            "key": "preserve_evidence_package",
            "priority": 4,
            "title": "Preserve all payment receipts, UTR numbers, and chat logs",
            "detail": "Take high-resolution screenshots with timestamps visible. Do not delete WhatsApp or SMS chat histories.",
        })

        donts.extend([
            "DO NOT send any additional money — fraudsters frequently demand 'processing fees' or 'refund validation payments'.",
            "DO NOT delete communications with the scammer; these are your primary legal evidence.",
            "DO NOT delay filing your complaint — banking recall success decreases sharply after 24 hours.",
        ])

    # 4. Sensitive Data Shared
    elif incident_type == "sensitive_data_shared":
        items = details.get("personal_data_items", [])
        if isinstance(items, str):
            items = [items]
        impersonation = details.get("impersonation_type", "none")

        severity = "CRITICAL" if any("aadhaar" in i or "card" in i for i in items) else "HIGH"
        risk_summary = f"Identity Exposure Risk: Shared {', '.join(items) if items else 'identifying data'}. Threat of synthetic identity theft and unauthorized banking."

        if impersonation == "police_digital_arrest":
            actions.append({
                "key": "digital_arrest_warning",
                "priority": 1,
                "title": "🚨 Digital Arrest Scam: Disconnect all video calls immediately",
                "detail": "Indian Police, CBI, ED, and Customs NEVER conduct arrests or court hearings over Skype/WhatsApp video calls. They cannot demand funds into 'RBI verification accounts'.",
            })

        if any("aadhaar" in i.lower() for i in items):
            actions.append({
                "key": "lock_aadhaar_biometrics",
                "priority": len(actions) + 1,
                "title": "Instantly lock Aadhaar Biometrics on myaadhaar.uidai.gov.in",
                "detail": "Locking biometrics stops fraud via AePS (Aadhaar Enabled Payment System) fingerprint and iris scanners.",
            })

        if any("card" in i.lower() or "cvv" in i.lower() for i in items):
            actions.append({
                "key": "block_cards_hotlist",
                "priority": len(actions) + 1,
                "title": "Block and hotlist credit/debit card immediately",
                "detail": "Call your card issuer to permanently block the card and issue a replacement with a new CVV.",
            })

        if any("pan" in i.lower() for i in items):
            actions.append({
                "key": "monitor_cibil_inquiries",
                "priority": len(actions) + 1,
                "title": "Check CIBIL / Experian report for unauthorized loan applications",
                "detail": "Scammers use stolen PAN and Aadhaar to open instant fintech loans in the victim's name.",
            })

        actions.append({
            "key": "lodge_loss_entry",
            "priority": len(actions) + 1,
            "title": "Register a Lost Document Report / Cyber cell notice",
            "detail": "Create a paper trail proving your identity documents were compromised to protect yourself from future liabilities.",
        })

        donts.extend([
            "Don't answer further verification calls or provide video KYC selfies to unknown entities.",
            "Don't share OTPs under threats of legal arrest, disconnection, or package seizure.",
        ])

    # 5. Suspicious App
    elif incident_type == "suspicious_app":
        app_type = details.get("app_type", "apk")
        severity = "CRITICAL"
        risk_summary = "Device Compromise / Remote Control: Malicious application may intercept SMS OTPs, read screen content, or allow remote keystroke logging."

        actions.append({
            "key": "enable_airplane_mode",
            "priority": 1,
            "title": "Turn on Airplane Mode & disconnect Wi-Fi right now",
            "detail": "Severing network access immediately cuts off the attacker's remote desktop stream and prevents data exfiltration.",
        })

        actions.append({
            "key": "remove_admin_and_uninstall",
            "priority": 2,
            "title": "Revoke Device Admin / Accessibility and uninstall the app",
            "detail": "Go to Settings > Apps > Special App Access > Device Admin Apps. Disable the rogue app, then uninstall it.",
        })

        actions.append({
            "key": "change_passwords_clean_pc",
            "priority": 3,
            "title": "Change all banking and email passwords from a different device",
            "detail": "Do not type passwords on the compromised phone. Use a trusted family member's phone or desktop computer.",
        })

        actions.append({
            "key": "inspect_banking_apps",
            "priority": 4,
            "title": "Inspect banking and UPI apps for unauthorized device registrations",
            "detail": "Log into your netbanking from a secure computer and check if unknown devices or UPI handles were linked.",
        })

        if "remote" in app_type.lower():
            actions.append({
                "key": "check_remote_tools",
                "priority": 5,
                "title": "Ensure AnyDesk / TeamViewer / QuickSupport sessions are killed",
                "detail": "Uninstall remote desktop software if you did not explicitly install it for verified enterprise IT support.",
            })

        donts.extend([
            "Don't enter netbanking passwords, UPI PINs, or screen lock patterns while the suspicious app is active.",
            "Don't connect your phone via USB cable to work or personal computers.",
            "Don't trust callers instructing you to install 'QuickSupport' or 'Screen Share' tools for KYC.",
        ])

    # Build dynamic helplines list
    helplines = [
        {
            "name": "National Cyber Crime Helpline (Emergency 24x7)",
            "contact": "1930",
            "url": "https://cybercrime.gov.in",
            "note": "Immediate toll-free hotline to initiate inter-bank freeze and stop payment transfer.",
        },
        {
            "name": "National Cyber Crime Reporting Portal",
            "contact": "cybercrime.gov.in",
            "url": "https://cybercrime.gov.in",
            "note": "Lodge an online cyber fraud complaint with digital evidence uploads.",
        },
    ]

    if bank_info:
        helplines.insert(0, {
            "name": f"{bank_name} Dedicated Fraud Desk",
            "contact": bank_info["phone"],
            "url": bank_info["portal"],
            "note": "Official 24/7 bank customer care fraud helpline for account/card blocking.",
        })

    if "aadhaar" in str(details).lower():
        helplines.append({
            "name": "Aadhaar Biometric Lock (UIDAI)",
            "contact": "myaadhaar.uidai.gov.in",
            "url": "https://myaadhaar.uidai.gov.in",
            "note": "Lock biometric authentication to stop unauthorized AePS cash withdrawals.",
        })

    return severity, golden_hour, risk_summary, actions, donts, helplines


def create_incident(
    incident_type: str, channel: str | None = None, details: dict[str, Any] | None = None
) -> dict:
    """Create a new incident with dynamically tailored actions based on user input."""
    if incident_type not in INCIDENT_LABELS:
        raise ValueError(f"Unknown incident type: {incident_type}")

    details = details or {}
    incident_id = f"inc_{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    severity, golden_hour, risk_summary, actions, donts, helplines = _evaluate_plan_and_severity(
        incident_type, details
    )

    # Check for correlated scan in RECENT_SCANS
    target_url = details.get("url", "").strip()
    correlated_scan = None
    if target_url:
        for s in RECENT_SCANS.list_recent(50):
            if target_url in s["url"] or s["url"] in target_url:
                correlated_scan = {
                    "url": s["url"],
                    "risk_score": s["risk_score"],
                    "label": s["label"],
                    "reasons": s["reasons"],
                }
                break

    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()

    details_with_meta = {
        **details,
        "risk_summary": risk_summary,
        "severity": severity,
        "golden_hour": golden_hour,
        "correlated_scan": correlated_scan,
    }

    c.execute(
        """INSERT INTO incidents (id, incident_type, channel, details, severity, golden_hour, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'action_required', ?)""",
        (
            incident_id,
            incident_type,
            channel,
            json.dumps(details_with_meta),
            severity,
            1 if golden_hour else 0,
            now,
        ),
    )

    action_records = []
    for action in actions:
        action_id = f"act_{uuid.uuid4().hex[:8]}"
        c.execute(
            """INSERT INTO incident_actions (id, incident_id, action_key, priority, title, detail, completed)
               VALUES (?, ?, ?, ?, ?, ?, 0)""",
            (action_id, incident_id, action["key"], action["priority"], action["title"], action.get("detail", "")),
        )
        action_records.append({
            "id": action_id,
            "priority": action["priority"],
            "title": action["title"],
            "detail": action.get("detail", ""),
            "completed": False,
            "completed_at": None,
        })

    conn.commit()
    conn.close()

    total = len(action_records)
    return {
        "incident_id": incident_id,
        "incident_type": incident_type,
        "incident_label": INCIDENT_LABELS.get(incident_type, incident_type),
        "severity": severity,
        "golden_hour": golden_hour,
        "risk_summary": risk_summary,
        "status": "action_required",
        "created_at": now,
        "closed_at": None,
        "details": details_with_meta,
        "progress": {"total": total, "completed": 0, "percentage": 0},
        "actions": action_records,
        "donts": donts,
        "helplines": helplines,
        "disclaimer": "These forensic recovery steps mitigate damage but cannot verify third-party system state. If financial losses occurred, report to 1930 immediately.",
    }


def get_incident(incident_id: str) -> dict | None:
    """Retrieve an incident with its dynamic metadata and actions."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return None

    incident = dict(row)

    c.execute("SELECT * FROM incident_actions WHERE incident_id = ? ORDER BY priority", (incident_id,))
    actions = [
        {
            "id": a["id"],
            "priority": a["priority"],
            "title": a["title"],
            "detail": a["detail"],
            "completed": bool(a["completed"]),
            "completed_at": a["completed_at"],
        }
        for a in c.fetchall()
    ]
    conn.close()

    try:
        parsed_details = json.loads(incident["details"] or "{}")
    except Exception:
        parsed_details = {}

    incident_type = incident["incident_type"]
    total = len(actions)
    done = sum(1 for a in actions if a["completed"])

    severity, golden_hour, risk_summary, _, donts, helplines = _evaluate_plan_and_severity(
        incident_type, parsed_details
    )

    return {
        "incident_id": incident["id"],
        "incident_type": incident_type,
        "incident_label": INCIDENT_LABELS.get(incident_type, incident_type),
        "severity": incident.get("severity", severity),
        "golden_hour": bool(incident.get("golden_hour", golden_hour)),
        "risk_summary": parsed_details.get("risk_summary", risk_summary),
        "status": incident["status"],
        "created_at": incident["created_at"],
        "closed_at": incident["closed_at"],
        "details": parsed_details,
        "progress": {"total": total, "completed": done, "percentage": round(done / total * 100) if total > 0 else 0},
        "actions": actions,
        "donts": donts,
        "helplines": helplines,
        "disclaimer": "These forensic recovery steps mitigate damage but cannot verify third-party system state. If financial losses occurred, report to 1930 immediately.",
    }


def toggle_action(incident_id: str, action_id: str) -> dict | None:
    """Toggle an action's completed status."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT * FROM incident_actions WHERE id = ? AND incident_id = ?", (action_id, incident_id))
    action = c.fetchone()
    if not action:
        conn.close()
        return None

    now = datetime.now(timezone.utc).isoformat()
    new_completed = 0 if action["completed"] else 1
    completed_at = now if new_completed else None

    c.execute(
        "UPDATE incident_actions SET completed = ?, completed_at = ? WHERE id = ?",
        (new_completed, completed_at, action_id),
    )
    conn.commit()
    conn.close()

    return get_incident(incident_id)


def close_incident(incident_id: str) -> dict | None:
    """Mark an incident as resolved."""
    conn = sqlite3.connect(str(DB_PATH))
    c = conn.cursor()

    c.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,))
    if not c.fetchone():
        conn.close()
        return None

    now = datetime.now(timezone.utc).isoformat()
    c.execute("UPDATE incidents SET status = 'resolved', closed_at = ? WHERE id = ?", (now, incident_id))
    conn.commit()
    conn.close()

    return get_incident(incident_id)


def generate_dossier(incident_id: str) -> str | None:
    """Generate a printable text FIR / Cybercrime Complaint Dossier."""
    incident = get_incident(incident_id)
    if not incident:
        return None

    details = incident.get("details", {})
    created = incident.get("created_at", "")
    actions = incident.get("actions", [])
    completed_actions = [a["title"] for a in actions if a["completed"]]
    pending_actions = [a["title"] for a in actions if not a["completed"]]

    dossier = f"""================================================================================
                    KAVACHX CYBER FRAUD INCIDENT DOSSIER
                      FOR SUBMISSION TO 1930 / CYBERCRIME.GOV.IN
================================================================================
Incident Reference Number : {incident['incident_id']}
Date & Time Logged        : {created}
Incident Classification   : {incident['incident_label']}
Assessed Threat Severity  : {incident['severity']}
Golden Hour Protocol      : {'ACTIVE (URGENT RECALL)' if incident['golden_hour'] else 'STANDARD'}

--------------------------------------------------------------------------------
1. INCIDENT CIRCUMSTANCES & VICTIM REPORT
--------------------------------------------------------------------------------
Summary Assessment :
{incident['risk_summary']}

Reported Specifics :
- Target Link / Web URL      : {details.get('url', 'N/A')}
- Account / Service Affected : {details.get('account_type', 'N/A')}
- Credentials Exposed        : {details.get('credential_type', 'N/A')}
- Payment Channel            : {details.get('payment_method', 'N/A')}
- Bank / Financial Provider  : {details.get('bank_name', 'N/A')}
- Approximate Amount Lost    : {details.get('amount_lost', 'N/A')}
- Transaction Reference / UTR: {details.get('transaction_id', 'N/A')}
- Time Since Incident        : {details.get('time_elapsed', 'N/A')}
- Scammer Phone / Contact    : {details.get('scammer_contact', 'N/A')}
- Impersonation Modus        : {details.get('impersonation_type', 'N/A')}

Additional Victim Notes :
{details.get('notes', 'None provided')}

--------------------------------------------------------------------------------
2. TECHNICAL FORENSIC CORRELATION (KAVACHX ENGINE)
--------------------------------------------------------------------------------
"""
    correlated = details.get("correlated_scan")
    if correlated:
        dossier += f"""Correlated Scanned Link : {correlated['url']}
KavachX Risk Score   : {correlated['risk_score']}/100 ({correlated['label'].upper()})
Identified Indicators  : {', '.join(correlated['reasons']) if correlated['reasons'] else 'Anomalous heuristics'}
"""
    else:
        dossier += "No prior local telemetry linked. Incident reported via manual intake.\n"

    dossier += f"""
--------------------------------------------------------------------------------
3. REMEDIATION & DAMAGE MITIGATION CHECKLIST
--------------------------------------------------------------------------------
Completed Steps ({len(completed_actions)}/{len(actions)}):
"""
    for item in completed_actions:
        dossier += f"  [x] {item}\n"

    if pending_actions:
        dossier += "\nPending / Recommended Next Steps:\n"
        for item in pending_actions:
            dossier += f"  [ ] {item}\n"

    dossier += """
--------------------------------------------------------------------------------
4. STATUTORY REPORTING INFORMATION
--------------------------------------------------------------------------------
National Cyber Crime Helpline : 1930 (Available 24x7)
Online Cyber Crime Portal     : https://cybercrime.gov.in
RBI Sachet Financial Portal   : https://sachet.rbi.org.in

Notice: This document is generated by KavachX AI to assist cybercrime authorities
and banking nodal officers in expedited investigation and account freezes.
================================================================================
"""
    return dossier
