path = r"c:\Users\hp\SGU_HackX\PhishLens\backend\app\services\scoring_service.py"
with open(path, "r", encoding="utf-8") as f:
    c = f.read()

target = """    raw_score = (
        scale_heuristic_score(url_score, dom_score)
        + threat_score
        + tls_score
        + domain_age_score
        + ml_result.adjustment
    )"""

replacement = """    raw_score = (
        scale_heuristic_score(url_score, dom_score)
        + threat_score
        + tls_score
        + domain_age_score
        + ml_result.adjustment
    )

    # Proactive zero-day phishing override:
    # When a domain clearly combines brand typosquatting with credential lures (combosquatting),
    # classify it directly as DANGEROUS (>= 75) to protect users before victim reports arrive.
    if features.typosquat_target and features.suspicious_keywords:
        raw_score = max(raw_score, 78)"""

c = c.replace(target, replacement)

with open(path, "w", encoding="utf-8") as f:
    f.write(c)
print("scoring_service.py updated with zero-day combosquat override!")
