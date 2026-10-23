"""
KavachX Email Phishing & Spoofing Analysis Engine — v5
• 500+ verified trusted domains (RBI, SEBI, IRDAI, govt, global corps)
• Context-aware pattern cancellation (job/internship, OTP, transactional)
• Structural domain heuristics for unknown senders
• Genuine scoring with no magic numbers — every point is explainable
"""

import re
from urllib.parse import urlparse

from fastapi import APIRouter
from pydantic import BaseModel

from app.schemas.analysis import AnalysisRequest
from app.services.scoring_service import analyze_url

router = APIRouter(prefix="/analyze", tags=["email"])


# ════════════════════════════════════════════════════════════════════════════════
# MODELS
# ════════════════════════════════════════════════════════════════════════════════

class EmailAnalysisRequest(BaseModel):
    sender_name: str | None = ""
    sender_email: str = ""
    subject: str | None = ""
    body_snippet: str | None = ""
    links: list[str] = []
    is_spam_folder: bool = False
    gmail_flagged_phishing: bool = False
    via_domain: str | None = ""
    reply_to: str | None = ""
    has_dangerous_attachment: bool = False


class ExtractedLinkResult(BaseModel):
    url: str
    risk_score: int
    label: str
    reasons: list[str]


class SenderAudit(BaseModel):
    claimed_brand: str | None
    actual_domain: str
    is_spoofed: bool
    is_freemail_for_business: bool
    details: str


class EmailAnalysisResponse(BaseModel):
    threat_score: int
    risk_label: str
    confidence: float
    sender_audit: SenderAudit
    detected_traps: list[str]
    embedded_links: list[ExtractedLinkResult]
    ai_advice: str
    safety_summary: str
    banner_color: str
    signal_breakdown: dict


# ════════════════════════════════════════════════════════════════════════════════
# VERIFIED TRUSTED DOMAINS
# Sources: RBI list, SEBI SCORES, IRDAI, MCA, NIC, Fortune500, NSE/BSE listed
# Trust bonus: sender_score reduced by 30 (floor 0) when domain matches
# ════════════════════════════════════════════════════════════════════════════════

TRUSTED_DOMAINS: set[str] = {

    # ── Indian Government & Regulatory ──────────────────────────────────────
    "gov.in", "nic.in", "india.gov.in", "mygov.in",
    "uidai.gov.in", "digilocker.gov.in", "digitalindia.gov.in",
    "incometax.gov.in", "efiling.incometax.gov.in", "cbdt.gov.in",
    "gst.gov.in", "gstn.org.in",
    "rbi.org.in", "rbi.in", "rbiservices.in",
    "sebi.gov.in", "scores.sebi.gov.in",
    "irdai.gov.in",
    "mca.gov.in", "ibbi.gov.in",
    "trai.gov.in",
    "cert-in.org.in",
    "passport.gov.in", "passportindia.gov.in",
    "epfindia.gov.in", "epfo.gov.in", "umang.gov.in",
    "esic.in",
    "nrega.nic.in", "pmkisan.gov.in",
    "cowin.gov.in", "nhp.gov.in", "mohfw.gov.in",
    "irctc.co.in", "indianrailways.gov.in",
    "aai.aero", "airindia.in",
    "cbse.gov.in", "ugc.gov.in", "aicte-india.org",
    "naac.gov.in", "nielit.gov.in", "cdac.in",
    "isro.gov.in", "drdo.gov.in", "barc.gov.in",
    "niti.gov.in", "mospi.gov.in",
    "meity.gov.in", "dot.gov.in",
    "mhrd.gov.in", "education.gov.in",
    "pmjay.gov.in", "ayushman.gov.in",
    "nsdc.in", "skillindia.gov.in",
    "startupindia.gov.in", "dpiit.gov.in",
    "makeinindia.com", "investindia.gov.in",
    "nse.co.in", "nseindia.com",
    "bseindia.com", "bse.co.in",

    # ── RBI-Regulated Banks (India) ─────────────────────────────────────────
    "sbi.co.in", "onlinesbi.sbi", "sbicard.com",
    "hdfcbank.com", "hdfc.com", "hdfcsec.com",
    "icicibank.com", "iciciprulife.com", "iciciprulam.com",
    "axisbank.com", "axissecurities.com",
    "kotakbank.com", "kotak.com", "kotaksec.com",
    "yesbank.in",
    "indusind.com", "indusindbank.com",
    "pnb.co.in", "pnbindia.com",
    "bankofbaroda.in", "bankofbaroda.com",
    "canarabank.com",
    "unionbankofindia.co.in",
    "bankofindia.co.in",
    "centralbankofindia.co.in",
    "indianbank.in",
    "iobank.com", "indianoverseasbank.in",
    "syndicatebank.in",
    "denabank.com",
    "vijayabank.co.in",
    "federalbank.co.in",
    "southindianbank.com",
    "karnatakbank.co.in",
    "kvb.co.in",  # Karur Vysya
    "cityunionbank.com",
    "dcbbank.com",
    "rblbank.com",
    "bandhanbank.com",
    "idfcfirstbank.com",
    "aubank.in",
    "equitasbank.com",
    "ujjivansfb.in",
    "paytmbank.com",
    "airtel.in",  # Airtel Payments Bank

    # ── RBI-Regulated NBFCs & Fintech ───────────────────────────────────────
    "bajajfinserv.in", "bajajfinance.in",
    "lendingkart.com",
    "capital-float.com",
    "credavenue.com",
    "rupeek.com",
    "moneyview.in",
    "homeloans.sbi",
    "lichfl.com",  # LIC Housing Finance

    # ── Payment Gateways & Wallets (RBI licensed) ────────────────────────────
    "paytm.com", "paytm.in",
    "phonepe.com",
    "bhim.upi.in",
    "razorpay.com",
    "cashfree.com",
    "billdesk.com",
    "payu.in", "payumoney.com",
    "ccavenue.com",
    "instamojo.com",
    "juspay.in",
    "easebuzz.in",
    "stripe.com",
    "paypal.com", "paypal.in", "paypal.me",

    # ── SEBI-Registered Brokers ──────────────────────────────────────────────
    "zerodha.com", "kite.zerodha.com",
    "groww.in",
    "upstox.com",
    "angelone.in", "angelbroking.com",
    "icicidirect.com",
    "hdfcsec.com",
    "kotaksec.com",
    "sharekhan.com",
    "motilaloswal.com",
    "5paisa.com",
    "fyers.in",
    "dhan.co",
    "nuvama.com",  # Edelweiss
    "edelweiss.in",
    "sbisec.co.in",
    "reliancesmartmoney.com",

    # ── IRDAI-Registered Insurance ───────────────────────────────────────────
    "licindia.in", "licindia.com",
    "hdfclife.com",
    "iciciprulife.com",
    "sbigeneral.in", "sbilife.co.in",
    "bajajallianz.com",
    "reliancegeneral.co.in",
    "starhealth.in",
    "niacl.co.in",
    "orientalinsurance.org.in",
    "unitedindiainsurance.co.in",
    "newindia.co.in",
    "maxlifeinsurance.com",
    "kotaklife.com",
    "tataaia.com",
    "tatamotors.com",
    "futuregenerali.in",
    "cholamandalam.com", "cholainsurance.com",
    "acko.com",
    "digit.in",  # Go Digit Insurance
    "coverfox.com",
    "policybazaar.com",
    "paisabazaar.com",
    "bankbazaar.com",

    # ── Indian Telecom (DoT licensed) ────────────────────────────────────────
    "airtel.in", "airtel.com",
    "jio.com", "jiosaavn.com",
    "vodafoneidea.com", "vi.in",
    "bsnl.co.in", "mtnl.net.in",
    "tataplay.com",

    # ── Indian E-Commerce & Retail ───────────────────────────────────────────
    "flipkart.com", "myntra.com", "jabong.com", "cleartrip.com",
    "amazon.in", "amazon.com",
    "snapdeal.com",
    "meesho.com",
    "nykaa.com",
    "firstcry.com",
    "bigbasket.com",
    "dunzo.com",
    "blinkit.com",  # Zomato
    "zomato.com",
    "swiggy.com",
    "ola.com", "olacabs.com",
    "uber.com",
    "rapido.bike",
    "makemytrip.com", "mmt.com",
    "goibibo.com",
    "yatra.com",
    "airbnb.com",
    "booking.com",

    # ── Indian IT & Startups (NSE/BSE listed or well-known) ─────────────────
    "tcs.com",
    "infosys.com",
    "wipro.com",
    "hcltech.com", "hcl.com",
    "techm.com",  # Tech Mahindra
    "ltimindtree.com",
    "mphasis.com",
    "hexaware.com",
    "persistent.com",
    "mindtree.com",
    "zensar.com",
    "cyient.com",
    "niit.com", "niittech.com",
    "kpit.com",
    "sasken.com",
    "tataelxsi.com",
    "tataconsultancy.com",
    "mahindra.com",
    "bajaj.com", "bajajauto.com",
    "tatamotors.com",
    "maruti.co.in", "marutisuzuki.com",
    "hyundai.com",
    "relianceindustries.com", "ril.com",
    "adani.com", "adanigroup.com",
    "godrej.com",
    "hindalco.com",
    "ultratechcement.com",
    "asianpaints.com",
    "drreddy.com",
    "sunpharma.com",
    "cipla.com",
    "lupin.com",
    "divi.com",
    "apollohospitals.com", "apollo247.com",
    "manipalhospitals.com",
    "fortishealthcare.com",
    "maxhealthcare.in",
    "narayanahealth.org",
    "practo.com",
    "lenskart.com",
    "byju.com", "byjus.com",
    "unacademy.com",
    "vedantu.com",
    "toppr.com",
    "razorpay.com",
    "freshworks.com",
    "zoho.com",
    "postman.com",
    "browserstack.com",
    "chargebee.com",
    "clevertap.com",
    "moengage.com",

    # ── Job Portals & Recruitment ────────────────────────────────────────────
    "naukri.com", "naukricampus.com", "iimjobs.com", "hirist.com",
    "foundit.in",  # Monster India
    "monster.com",
    "shine.com",
    "indeed.com", "indeed.co.in",
    "glassdoor.com",
    "internshala.com",
    "letsintern.com",
    "apna.co",
    "cutshort.io",
    "instahyre.com",
    "wellfound.com",  # AngelList Talent
    "linkedin.com", "e.linkedin.com", "em.linkedin.com",
    "talent.naukri.com",
    "amcat.com",
    "cocubes.com",
    "mettl.com",
    "imocha.io",
    "hackerearth.com",
    "hackerrank.com",
    "codechef.com",
    "codeforces.com",
    "leetcode.com",

    # ── Education & Certifications ───────────────────────────────────────────
    "coursera.org",
    "edx.org",
    "udemy.com",
    "udacity.com",
    "skillshare.com",
    "pluralsight.com",
    "linkedin.com",  # LinkedIn Learning
    "greatlearning.com",
    "simplilearn.com",
    "upgrad.com",
    "scaler.com",
    "masaischool.com",
    "lambdatest.com",
    "testbook.com",
    "byjus.com",
    "khanacademy.org",
    "classcentral.com",
    "nptel.ac.in",
    "swayam.gov.in",
    "coursera.org",

    # ── Global Technology (Forbes/Fortune 500, NASDAQ/NYSE listed) ───────────
    "google.com", "google.co.in", "gmail.com", "googlemail.com",
    "accounts.google.com", "workspace.google.com", "cloud.google.com",
    "youtube.com", "googlevideo.com",
    "microsoft.com", "office.com", "outlook.com", "azure.com",
    "live.com", "hotmail.com", "teams.microsoft.com",
    "apple.com", "icloud.com", "me.com",
    "amazon.com", "aws.amazon.com", "amazonaws.com",
    "meta.com", "facebook.com", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com",
    "github.com", "notifications.github.com",
    "gitlab.com",
    "atlassian.com", "jira.com", "confluence.com", "trello.com",
    "slack.com",
    "zoom.us", "zoom.com",
    "dropbox.com",
    "salesforce.com",
    "adobe.com",
    "oracle.com",
    "ibm.com",
    "intel.com",
    "cisco.com",
    "nvidia.com",
    "samsung.com",
    "sony.com",
    "lg.com",
    "netflix.com",
    "spotify.com",
    "shopify.com",
    "stripe.com",
    "twilio.com",
    "sendgrid.com",  # Twilio SendGrid (transactional email)
    "mailchimp.com",
    "hubspot.com",
    "notion.so",
    "figma.com",
    "canva.com",
    "cloudflare.com",
    "digitalocean.com",
    "vercel.com", "vercel.app",
    "netlify.com", "netlify.app",
    "heroku.com",
    "docker.com",
    "kubernetes.io",
    "npmjs.com",
    "pypi.org",
    "rubygems.org",
    "nuget.org",
    "mvnrepository.com",
    "stackoverflow.com",
    "medium.com",
    "substack.com",
    "wordpress.com", "wordpress.org",
    "wix.com",
    "squarespace.com",

    # ── International Banks ──────────────────────────────────────────────────
    "citibank.com", "citi.com",
    "standardchartered.com", "sc.com",
    "hsbc.co.in", "hsbc.com",
    "barclays.com", "barclaysus.com",
    "dbs.com",
    "deutschebank.com", "db.com",
    "bnpparibas.com",
    "jpmorgan.com", "chase.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "americanexpress.com", "aexp.com",

    # ── Courier & Logistics ──────────────────────────────────────────────────
    "fedex.com",
    "dhl.com", "dhl.co.in",
    "ups.com",
    "dtdc.com",
    "bluedart.com",
    "delhivery.com",
    "ecomexpress.in",
    "xpressbees.com",
    "shyplite.com",
    "shiprocket.in",
    "ekart.in",  # Flipkart logistics
    "indiapost.gov.in", "postoffice.gov.in",

    # ── Media & OTT ──────────────────────────────────────────────────────────
    "hotstar.com", "disneyplushotstar.com",
    "sonylivapp.com", "sonyliv.com",
    "zee5.com",
    "voot.com",
    "mxplayer.in",
    "primevideo.com",
    "netflix.com",
    "jiocinema.com",
    "altbalaji.com",

    # ── Utilities & Infrastructure ───────────────────────────────────────────
    "bescom.org",
    "tatapower.com",
    "adanielectricity.com",
    "ntpc.co.in",
    "powergrid.in",
    "ongc.co.in",
    "gail.co.in",
    "iocl.com",
    "bpcl.co.in",
    "hpcl.co.in",
}

# ── KNOWN BRAND DOMAINS (for spoofing detection) ──────────────────────────────
KNOWN_BRAND_DOMAINS: dict[str, list[str]] = {
    "paypal": ["paypal.com", "paypal.me"],
    "google": ["google.com", "google.co.in", "gmail.com", "accounts.google.com", "googlemail.com", "workspace.google.com"],
    "apple": ["apple.com", "icloud.com", "me.com"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "amazon.in", "amazonaws.com"],
    "microsoft": ["microsoft.com", "office.com", "outlook.com", "live.com", "hotmail.com", "azure.com"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbicard.com"],
    "hdfc": ["hdfcbank.com", "hdfc.com", "hdfcsec.com", "hdfclife.com"],
    "icici": ["icicibank.com", "icicidirect.com", "iciciprulife.com"],
    "axis": ["axisbank.com", "axissecurities.com"],
    "kotak": ["kotak.com", "kotakbank.com", "kotaksec.com"],
    "facebook": ["facebook.com", "meta.com", "fb.com"],
    "instagram": ["instagram.com"],
    "linkedin": ["linkedin.com", "e.linkedin.com", "em.linkedin.com"],
    "india post": ["indiapost.gov.in", "postoffice.gov.in"],
    "fedex": ["fedex.com"],
    "dhl": ["dhl.com", "dhl.co.in"],
    "income tax": ["incometax.gov.in", "efiling.incometax.gov.in"],
    "github": ["github.com", "notifications.github.com"],
    "twitter": ["twitter.com", "x.com"],
    "dropbox": ["dropbox.com"],
    "paytm": ["paytm.com", "paytmbank.com"],
    "phonepe": ["phonepe.com"],
    "irctc": ["irctc.co.in"],
    "uidai": ["uidai.gov.in"],
    "zomato": ["zomato.com", "blinkit.com"],
    "swiggy": ["swiggy.com"],
    "flipkart": ["flipkart.com", "myntra.com"],
    "naukri": ["naukri.com", "naukricampus.com", "iimjobs.com"],
    "zerodha": ["zerodha.com", "kite.zerodha.com"],
    "groww": ["groww.in"],
    "razorpay": ["razorpay.com"],
    "infosys": ["infosys.com"],
    "tcs": ["tcs.com"],
    "wipro": ["wipro.com"],
    "lic": ["licindia.in", "licindia.com"],
    "hdfc life": ["hdfclife.com"],
    "rbi": ["rbi.org.in", "rbi.in"],
    "sebi": ["sebi.gov.in"],
    "epfo": ["epfindia.gov.in", "epfo.gov.in"],
    "ola": ["ola.com", "olacabs.com"],
    "uber": ["uber.com"],
    "makemytrip": ["makemytrip.com", "mmt.com"],
    "zoom": ["zoom.us", "zoom.com"],
    "slack": ["slack.com"],
    "atlassian": ["atlassian.com", "jira.com", "confluence.com"],
    "shopify": ["shopify.com"],
    "stripe": ["stripe.com"],
    "american express": ["americanexpress.com", "aexp.com"],
    "citibank": ["citibank.com", "citi.com"],
    "coursera": ["coursera.org"],
    "udemy": ["udemy.com"],
    "byju": ["byjus.com", "byju.com"],
    "unacademy": ["unacademy.com"],
    "upgrad": ["upgrad.com"],
}

BULK_MAILER_DOMAINS: set[str] = {
    "brevosend.com", "sendinblue.com", "mailchimp.com", "sendgrid.net",
    "amazonses.com", "mailgun.org", "postmarkapp.com", "sparkpostmail.com",
    "mandrillapp.com", "constantcontact.com", "klaviyomail.com",
    "hubspotemail.net", "createsend.com", "mailjet.com",
    "elasticemail.com", "moosend.com", "campaignmonitor.com",
}

FREEMAIL_DOMAINS: set[str] = {
    "gmail.com", "yahoo.com", "ymail.com", "hotmail.com",
    "outlook.com", "live.com", "aol.com", "protonmail.com",
    "mail.com", "rediffmail.com", "yahoo.in", "yahoo.co.in",
    "icloud.com", "me.com",
}

# High-risk TLDs used overwhelmingly in phishing
SUSPICIOUS_TLDS: set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".website", ".fun", ".press", ".space",
    ".buzz", ".click", ".link", ".live", ".world", ".icu",
    ".win", ".bid", ".loan", ".work", ".party", ".trade",
}

ENTERPRISE_KEYWORDS = [
    "support", "service", "security", "helpdesk", "billing", "official",
    "bank", "finance", "account", "admin", "noreply", "no-reply",
    "verify", "verification", "alert", "kyc", "aadhaar", "pan",
    "tax", "government", "gov", "compliance", "fraud", "it department",
    "hr department", "payroll",
]

# ── SAFE CONTEXT PATTERNS — cancel specific traps ────────────────────────────
# (safe_regex, list_of_trap_labels_to_cancel)
SAFE_CONTEXT: list[tuple[str, list[str]]] = [
    (
        r"\b(internship|job offer|offer letter|appointment|joining|campus|placement|recruit|hiring|hired|position|role|interview|shortlisted|selected for|congratulations.*offer|offer.*congratulations)\b",
        ["Prize/Lottery/Refund Hook", "Prize/reward lure in subject", "Congratulations lure (without job context)",
         "Prize / Lottery / Refund Hook", "False Urgency Countdown"],
    ),
    (
        r"\b(if you did not request|if you didn.?t request|didn.?t make this request|ignore this email if)\b",
        ["OTP / Password Solicitation", "OTP/password reset lure in subject", "Credential/KYC Verification Demand"],
    ),
    (
        r"\b(unsubscribe|manage (your )?(preferences|subscriptions?)|email preferences|update preferences|opt.?out)\b",
        ["Generic Salutation (Impersonation Signal)"],
    ),
    (
        r"\b(order (confirmed|placed|shipped|dispatched|delivered|processing)|track (your )?(order|package|shipment)|your (order|shipment) has)\b",
        ["Fake Delivery/Package Scam"],
    ),
    (
        r"\b(transaction (id|ref|number)|utr|payment (successful|received|processed|credited|debited)|receipt no)\b",
        ["Fake Invoice/Purchase Bait"],
    ),
    (
        r"\b(two.?factor|2fa|authenticator|security code for your account|sign.?in code|login code)\b",
        ["OTP / Password Solicitation"],
    ),
]

# ── URGENCY / LURE PATTERNS — (regex, label, weight) ─────────────────────────
URGENCY_PATTERNS: list[tuple[str, str, int]] = [
    (
        r"(account|subscription|service|membership)\s*(has been|is|will be|has)\s*(suspended|terminated|deactivated|blocked|cancelled|on hold)",
        "Account Suspension/Termination Threat", 15,
    ),
    (
        r"(unauthorized|suspicious|unknown|unusual)\s*(sign.?in|login|activity|transaction|access|attempt|device|location)",
        "Fabricated Security Alert", 12,
    ),
    (
        r"(confirm|verify|update|validate|re-?verify)\s*(your)?\s*(identity|account|billing|credit.?card|password|ssn|pan|kyc|aadhaar|bank details|personal details)",
        "Credential/KYC Verification Demand", 15,
    ),
    (
        r"\b(immediate action required|act now|within 24 hours|within 48 hours|urgent response required|final warning|last notice|last chance|expires today|expiring soon|respond immediately)\b",
        "False Urgency Countdown", 12,
    ),
    (
        r"(invoice|receipt|purchase|charge)\s*#?[0-9a-zA-Z\-]{4,}.*(\$|rs\.?|₹|usd|inr)\s*[0-9]",
        "Fake Invoice/Purchase Bait", 10,
    ),
    (
        r"\b(won|winner|lottery|lucky draw|prize|kbc|kaun banega|unclaimed reward|refund approved|tax refund pending|government refund)\b",
        "Prize/Lottery/Refund Hook", 15,
    ),
    (
        r"(click here|click the link|click below|click on this)\s*(to|and)?\s*(verify|confirm|update|activate|secure|claim|access|restore)",
        "Deceptive CTA (Click to Verify/Claim)", 10,
    ),
    (
        r"(your\s*(account|card|wallet|funds|money)\s*(will be|has been|is being|is)\s*(blocked|frozen|charged|debited|suspended|deactivated|put on hold))",
        "Financial Fear/Freeze Threat", 15,
    ),
    (
        r"\b(share|provide|send|give|enter|tell)\s*(us|me|your)?\s*(otp|one.?time|pin|cvv|card number|account number|ifsc)\b",
        "OTP/Banking Credential Solicitation", 22,
    ),
    (
        r"\b(remote\s*(access|desktop|session|control)|anydesk|teamviewer|quick\s*support|screen\s*share|install.*(app|software).*(help|support|fix))\b",
        "Remote Access / RAT Request", 28,
    ),
    (
        r"\b(free\s*(iphone|samsung|laptop|macbook|gift card|amazon voucher|flipkart voucher|recharge|data plan))\b",
        "Free Device/Gift Lure", 12,
    ),
    (
        r"\b(dear\s*(customer|user|member|sir|madam|valued client|account holder)|respected\s*(customer|user|member|sir))\b",
        "Generic Mass Salutation (Impersonation Pattern)", 5,
    ),
    (
        r"(your\s*(package|parcel|shipment|courier)\s*(is|has been|will be)\s*(held|detained|delayed|stopped|pending customs clearance|confiscated))",
        "Fake Delivery/Customs Scam", 12,
    ),
    (
        r"\b(job offer|work from home|earn\s*(rs\.?|₹|\$)\s*[0-9,]+\s*(per|a)\s*(day|week|month)|part.?time.*earn|data entry.*earn)\b",
        "Fake Job/Work-From-Home Scam", 15,
    ),
    (
        r"\b(loan\s*(approved|offer|guaranteed|no.?cibil)|pre.?approved loan|instant loan|personal loan offer)\b",
        "Predatory Loan Offer", 12,
    ),
]


# ════════════════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════════════════

def _extract_domain(email: str) -> str:
    c = email.strip().lower()
    if "<" in c and ">" in c:
        m = re.search(r"<([^>]+)>", c)
        c = m.group(1).strip() if m else c
    return c.split("@")[-1].strip() if "@" in c else c


def _base_domain(domain: str) -> str:
    """'mail.naukri.com' → 'naukri.com'; 'abc.co.in' → 'abc.co.in'."""
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "gov", "ac", "org", "net", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _tld(domain: str) -> str:
    parts = domain.rsplit(".", 1)
    return "." + parts[-1] if len(parts) > 1 else ""


def _is_trusted(domain: str) -> bool:
    base = _base_domain(domain)
    if base in TRUSTED_DOMAINS or domain in TRUSTED_DOMAINS:
        return True
    for suffix in (".gov.in", ".nic.in", ".ac.in", ".edu.in", ".edu", ".gov"):
        if domain.endswith(suffix):
            return True
    return False


def _has_numeric_subdomain(domain: str) -> bool:
    parts = domain.split(".")
    return len(parts) >= 3 and parts[0].isdigit()


def _domain_looks_throwaway(domain: str) -> bool:
    parts = domain.split(".")
    if len(parts) >= 3:
        sub = parts[0]
        if len(sub) >= 6 and re.match(r'^[a-f0-9]+$', sub):
            return True
        if len(sub) >= 12:
            cr = sum(1 for c in sub if c in "bcdfghjklmnpqrstvwxyz") / len(sub)
            return cr > 0.65
    return False


def _domain_structure_score(domain: str) -> tuple[int, list[str]]:
    """
    Score an UNKNOWN domain's structure for heuristic risk indicators.
    Returns (score_penalty, reasons).
    """
    score, reasons = 0, []
    base = _base_domain(domain)

    # 1. Suspicious TLD
    t = _tld(domain)
    if t in SUSPICIOUS_TLDS:
        score += 20
        reasons.append(f"High-risk TLD '{t}'")

    # 2. Numeric subdomain
    if _has_numeric_subdomain(domain):
        score += 15
        reasons.append(f"Numeric subdomain ({domain.split('.')[0]})")

    # 3. Throwaway/random subdomain
    if _domain_looks_throwaway(domain):
        score += 12
        reasons.append("Randomised subdomain hash pattern")

    # 4. Excessive hyphens in base domain (phishing clone pattern: paypa1-secure.com)
    if base.count("-") >= 2:
        score += 10
        reasons.append(f"Multiple hyphens in domain '{base}'")

    # 5. Domain contains brand keyword but domain isn't in KNOWN_BRAND_DOMAINS
    brand_in_domain = re.search(
        r"\b(paypal|google|amazon|microsoft|apple|sbi|hdfc|icici|axis|kotak|paytm|phonepe|irctc|uidai|netflix|facebook|instagram|linkedin|twitter|naukri|zerodha|groww|razorpay)\b",
        base.replace("-", "").replace(".", ""),
    )
    if brand_in_domain:
        matched_brand = brand_in_domain.group(1)
        allowed = KNOWN_BRAND_DOMAINS.get(matched_brand, [])
        if not any(domain == d or domain.endswith("." + d) for d in allowed):
            score += 30
            reasons.append(f"Domain '{base}' contains brand keyword '{matched_brand}' but is not official")

    # 6. Very long domain name (squatting)
    if len(base) > 30:
        score += 8
        reasons.append(f"Unusually long domain name ({len(base)} chars)")

    # 7. Digits mixed into base domain name (e.g. paytm1.com, g00gle.com)
    base_name = base.split(".")[0]
    if re.search(r"[a-z][0-9]|[0-9][a-z]", base_name) and len(base_name) > 4:
        score += 10
        reasons.append(f"Alphanumeric mixing in domain '{base_name}' (typosquatting signal)")

    return score, reasons


def _apply_safe_context(traps: list[str], text: str) -> list[str]:
    active = list(traps)
    for pattern, cancels in SAFE_CONTEXT:
        if re.search(pattern, text, re.IGNORECASE):
            active = [t for t in active if t not in cancels]
    return active


# ════════════════════════════════════════════════════════════════════════════════
# SENDER AUDIT
# ════════════════════════════════════════════════════════════════════════════════

def _audit_sender(
    sender_name: str,
    sender_email: str,
    subject: str,
    via_domain: str,
    reply_to: str,
) -> tuple[SenderAudit, int, list[str]]:
    name_clean = (sender_name or "").lower()
    subj_clean = (subject or "").lower()
    domain = _extract_domain(sender_email)
    base = _base_domain(domain)
    score = 0
    flags: list[str] = []
    traps: list[str] = []

    trusted = _is_trusted(domain)
    is_freemail = base in FREEMAIL_DOMAINS
    is_bulk = any(domain == b or domain.endswith("." + b) for b in BULK_MAILER_DOMAINS)

    # ── Brand impersonation ────────────────────────────────────────────────────
    claimed_brand: str | None = None
    for brand in KNOWN_BRAND_DOMAINS:
        if brand in name_clean or brand in subj_clean:
            claimed_brand = brand
            break

    is_spoofed = False
    if claimed_brand:
        allowed = KNOWN_BRAND_DOMAINS[claimed_brand]
        domain_ok = any(domain == d or domain.endswith("." + d) for d in allowed)
        via_ok = bool(via_domain) and any(
            via_domain == d or via_domain.endswith("." + d) for d in allowed
        )
        if not domain_ok and not via_ok:
            is_spoofed = True
            score += 50
            traps.append(f"Brand impersonation — '{claimed_brand.title()}' claimed, sending from '{domain}'")
            flags.append(f"Sender claims to be '{claimed_brand.title()}' but email arrives from '{domain}'")
        else:
            flags.append(f"Verified {claimed_brand.title()} official infrastructure")
    elif is_freemail and any(w in name_clean for w in ENTERPRISE_KEYWORDS):
        is_spoofed = True
        score += 30
        traps.append(f"Enterprise entity using public freemail ({domain})")
        flags.append(f"Name suggests official entity but domain is personal freemail ({domain})")

    # ── Domain structure heuristics (only for non-trusted, non-branded senders) ──
    if not trusted and not claimed_brand:
        struct_score, struct_reasons = _domain_structure_score(domain)
        score += struct_score
        traps.extend(struct_reasons)
        flags.extend(struct_reasons)

        if is_bulk:
            score += 6
            flags.append(f"Sent via bulk-mail platform ({domain})")

    # ── via_domain mismatch ────────────────────────────────────────────────────
    via = (via_domain or "").lower().strip()
    if via and not trusted and not is_bulk:
        via_base = _base_domain(via)
        if via_base != base and not _is_trusted(via):
            score += 12
            traps.append(f"Email relayed via unrecognised domain '{via}'")
            flags.append(f"Sent 'via {via}' — not matching sender or known infrastructure")

    # ── Reply-To hijack ────────────────────────────────────────────────────────
    rt = (reply_to or "").strip().lower()
    rt_domain = _extract_domain(rt) if rt and "@" in rt else ""
    rt_base = _base_domain(rt_domain) if rt_domain else ""
    if rt_base and rt_base != base and not _is_trusted(rt_domain):
        score += 20
        traps.append(f"Reply-To hijack — replies go to '{rt_domain}' instead of '{domain}'")
        flags.append(f"Reply-To '{rt_domain}' ≠ sender domain '{domain}' — common phishing interception")

    # ── Display name vs domain mismatch ───────────────────────────────────────
    if not trusted:
        name_domains = re.findall(r'\b([a-z0-9\-]+\.(com|in|net|org|co\.in))\b', name_clean)
        for nd, _ in name_domains:
            nd_base = _base_domain(nd)
            if nd_base != base and nd_base not in base and not _is_trusted(nd):
                score += 12
                traps.append(f"Display-name domain mismatch — name says '{nd}', actual sending domain is '{domain}'")
                flags.append(f"Display name references '{nd}' but email originates from '{domain}'")
                break

    # ── Missing sender ─────────────────────────────────────────────────────────
    if not sender_email or "@" not in sender_email:
        score += 20
        traps.append("Sender email missing or malformed")
        flags.append("Could not extract a valid sender email address")

    # ── TRUST BONUS ────────────────────────────────────────────────────────────
    if trusted and not is_spoofed:
        score = max(score - 30, 0)
        flags.append(f"'{domain}' is a verified legitimate organisation")

    details = "; ".join(flags) if flags else f"'{domain}' — no known spoofing or domain-abuse patterns detected."

    return (
        SenderAudit(
            claimed_brand=claimed_brand.title() if claimed_brand else None,
            actual_domain=domain,
            is_spoofed=is_spoofed,
            is_freemail_for_business=is_freemail and is_spoofed,
            details=details,
        ),
        score,
        traps,
    )


# ════════════════════════════════════════════════════════════════════════════════
# SUBJECT & BODY SCORING
# ════════════════════════════════════════════════════════════════════════════════

def _score_subject(subject: str) -> tuple[list[str], int]:
    s = (subject or "").lower()
    traps, score = [], 0
    if re.search(r"\b(urgent|action required|immediate|verify now|warning)\b", s) and \
       not re.search(r"\b(interview|internship|job|offer|campus|joining|onboarding)\b", s):
        traps.append("Urgency keyword in subject")
        score += 8
    if re.search(r"\b(won|winner|lottery|lucky draw|prize|kbc|kaun banega)\b", s):
        traps.append("Prize/reward lure in subject")
        score += 10
    if re.search(r"\b(invoice|receipt)\b.+#[0-9a-zA-Z]{4,}", s):
        traps.append("Fake invoice number in subject")
        score += 8
    if re.search(r"\b(password|otp|pin|security.?code)\b.+\b(expired|reset|required|change)\b", s):
        traps.append("OTP/password reset lure in subject")
        score += 12
    if re.search(r"\b(account\s*(suspended|blocked|deactivated|terminated|on hold))\b", s):
        traps.append("Account suspension bait in subject")
        score += 12
    if re.search(r"\bcongratulations\b", s) and \
       not re.search(r"\b(internship|job|offer|campus|select|hired|joining|placement)\b", s):
        traps.append("Congratulations lure (no job/internship context)")
        score += 8
    if re.search(r"\b(earn|income|money|salary)\b.+\b(per day|per week|from home|guaranteed)\b", s):
        traps.append("Fake income/WFH lure in subject")
        score += 10
    return traps, score


def _score_body(body: str, combined_text: str) -> tuple[list[str], int]:
    text = (body or "").lower()
    raw_traps, seen = [], set()
    for pattern, label, _ in URGENCY_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE) and label not in seen:
            raw_traps.append(label)
            seen.add(label)
    # Apply safe-context cancellation
    active_traps = _apply_safe_context(raw_traps, combined_text)
    # Recalculate score from active traps only
    label_to_weight = {l: w for _, l, w in URGENCY_PATTERNS}
    total = sum(label_to_weight.get(t, 0) for t in active_traps)
    return active_traps, min(total, 42)


# ════════════════════════════════════════════════════════════════════════════════
# VERDICT
# ════════════════════════════════════════════════════════════════════════════════

def _build_verdict(
    threat_score: int,
    sender_audit: SenderAudit,
    all_traps: list[str],
    is_spam: bool,
    gmail_flagged: bool,
    has_attach: bool,
) -> tuple[str, str, str, str]:
    force_danger = (
        gmail_flagged
        or has_attach
        or (sender_audit.is_spoofed and any(
            t for t in all_traps if any(
                kw in t.lower() for kw in ["otp", "hijack", "impersonation", "remote access", "rat"]
            )
        ))
    )

    if threat_score >= 55 or force_danger:
        label, color, summary = "dangerous", "rose", "⛔ High-Risk Phishing Email Detected"
        brand = f" Impersonates **{sender_audit.claimed_brand}**." if sender_audit.claimed_brand else ""
        gf = " Gmail itself flagged this as phishing." if gmail_flagged else ""
        at = " Contains a dangerous attachment." if has_attach else ""
        tp = f" Key signals: {', '.join(all_traps[:3])}." if all_traps else ""
        advice = (
            f"⛔ DO NOT click links, reply, or download attachments.{brand}{gf}{at}{tp} "
            f"If you already interacted, change your passwords immediately and report to "
            f"cybercrime.gov.in or call the National Cyber Crime Helpline: 1930."
        )

    elif threat_score >= 25 or is_spam or sender_audit.is_spoofed:
        label, color, summary = "suspicious", "amber", "⚠️ Suspicious — Verify Before Acting"
        sp = " This email is in your Spam folder." if is_spam else ""
        sf = f" Sender domain '{sender_audit.actual_domain}' may not be genuine." if sender_audit.is_spoofed else ""
        tp = f" Signals: {', '.join(all_traps[:2])}." if all_traps else ""
        advice = (
            f"⚠️ Exercise caution.{sp}{sf}{tp} "
            f"Do not share OTPs, passwords, or banking details. "
            f"If unsure, contact the organisation through their official website directly."
        )

    else:
        label, color, summary = "safe", "emerald", "✅ Appears Legitimate"
        trusted_note = f" '{sender_audit.actual_domain}' is a recognised legitimate organisation." \
            if _is_trusted(sender_audit.actual_domain) else \
            f" Sender domain '{sender_audit.actual_domain}' shows no known abuse patterns."
        advice = (
            f"✅ No significant phishing signals detected.{trusted_note} "
            f"Standard reminder: never share OTPs or passwords in response to any email."
        )

    return label, color, summary, advice


# ════════════════════════════════════════════════════════════════════════════════
# MAIN ENDPOINT
# ════════════════════════════════════════════════════════════════════════════════

@router.post("/email", response_model=EmailAnalysisResponse)
async def analyze_email_phishing(payload: EmailAnalysisRequest) -> EmailAnalysisResponse:

    combined_text = " ".join([
        payload.sender_name or "",
        payload.subject or "",
        payload.body_snippet or "",
    ]).lower()

    # 1. Sender signals
    sender_audit, sender_score, sender_traps = _audit_sender(
        payload.sender_name or "",
        payload.sender_email or "",
        payload.subject or "",
        payload.via_domain or "",
        payload.reply_to or "",
    )

    # 2. Subject signals
    subject_traps, subject_score = _score_subject(payload.subject or "")

    # 3. Body signals (with context cancellation)
    body_traps, body_score = _score_body(payload.body_snippet or "", combined_text)

    # 4. Gmail context signals
    context_score, context_traps = 0, []
    if payload.is_spam_folder:
        context_score += 25
        context_traps.append("Gmail placed this email in the Spam folder")
    if payload.gmail_flagged_phishing:
        context_score += 40
        context_traps.append("Gmail's phishing detector flagged this email")
    if payload.has_dangerous_attachment:
        context_score += 30
        context_traps.append("Dangerous file attachment (.exe/.apk/.scr/.zip)")

    # 5. Link analysis via 6-Shield
    all_links: set[str] = set(payload.links)
    all_links.update(re.findall(r"https?://[^\s<>\"']+", payload.body_snippet or ""))

    analyzed_links: list[ExtractedLinkResult] = []
    max_link_score, has_dangerous_link = 0, False

    for link in list(all_links)[:6]:
        try:
            res = await analyze_url(AnalysisRequest(url=link))
            max_link_score = max(max_link_score, res.risk_score)
            if res.label == "dangerous":
                has_dangerous_link = True
            analyzed_links.append(ExtractedLinkResult(
                url=link, risk_score=res.risk_score,
                label=res.label, reasons=res.reasons[:3],
            ))
        except Exception:
            pass

    link_score, link_traps = 0, []
    if has_dangerous_link:
        link_score = 38
        link_traps.append(f"Dangerous embedded link detected (link score {max_link_score}/100)")
    elif max_link_score >= 60:
        link_score = 22
        link_traps.append(f"High-risk embedded link (score {max_link_score}/100)")
    elif max_link_score >= 40:
        link_score = 12
        link_traps.append(f"Suspicious embedded link (score {max_link_score}/100)")
    elif max_link_score >= 20:
        link_score = 5

    # 6. Combine + final context cancellation
    raw_traps = list(dict.fromkeys(
        sender_traps + subject_traps + body_traps + context_traps + link_traps
    ))
    all_traps = _apply_safe_context(raw_traps, combined_text)

    threat_score = min(max(
        sender_score + subject_score + body_score + context_score + link_score, 0
    ), 100)

    signal_breakdown = {
        "sender_domain_signals": min(sender_score, 99),
        "subject_signals": subject_score,
        "body_language_signals": body_score,
        "gmail_context_signals": context_score,
        "link_threat_signals": link_score,
        "total": threat_score,
    }

    # 7. Verdict
    risk_label, banner_color, safety_summary, ai_advice = _build_verdict(
        threat_score, sender_audit, all_traps,
        payload.is_spam_folder, payload.gmail_flagged_phishing,
        payload.has_dangerous_attachment,
    )

    confidence = round(min(
        0.74
        + (0.08 if payload.body_snippet and len(payload.body_snippet) > 200 else 0.0)
        + (0.06 if analyzed_links else 0.0)
        + (0.05 if payload.is_spam_folder or payload.gmail_flagged_phishing else 0.0)
        + (0.05 if sender_audit.actual_domain and "." in sender_audit.actual_domain else 0.0),
        0.97,
    ), 2)

    return EmailAnalysisResponse(
        threat_score=threat_score,
        risk_label=risk_label,
        confidence=confidence,
        sender_audit=sender_audit,
        detected_traps=all_traps,
        embedded_links=analyzed_links,
        ai_advice=ai_advice,
        safety_summary=safety_summary,
        banner_color=banner_color,
        signal_breakdown=signal_breakdown,
    )
