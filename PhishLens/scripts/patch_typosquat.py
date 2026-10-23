import re

path = r"c:\Users\hp\SGU_HackX\PhishLens\backend\app\services\feature_extractor.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Replace SUSPICIOUS_KEYWORDS
old_kw_pattern = r"SUSPICIOUS_KEYWORDS = \([^)]+\)"
new_kw = """SUSPICIOUS_KEYWORDS = (
    "login",
    "verify",
    "verification",
    "account",
    "secure",
    "security",
    "update",
    "password",
    "bank",
    "banking",
    "wallet",
    "signin",
    "support",
    "portal",
    "auth",
    "billing",
    "confirm",
    "alert",
)"""
content = re.sub(old_kw_pattern, new_kw, content)

# Replace _is_hyphen_delimited_combo function
old_combo_pattern = r"def _is_hyphen_delimited_combo\(domain_label: str, brand_label: str\) -> bool:[\s\S]*?return brand_label in \(token for token in domain_label\.split\(\"-\"\) if token\)"
new_combo = """def _is_hyphen_delimited_combo(domain_label: str, brand_label: str) -> bool:
    if domain_label == brand_label:
        return False
    if brand_label in domain_label:
        return True
    tokens = [token for token in domain_label.split("-") if token]
    for token in tokens:
        if token == brand_label:
            return True
        if len(token) >= MIN_BRAND_NAME_LENGTH and _levenshtein_distance(token, brand_label) <= 1:
            return True
    return False"""
content = re.sub(old_combo_pattern, new_combo, content)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("feature_extractor.py patched successfully!")
