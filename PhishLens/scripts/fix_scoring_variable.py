path = r"c:\Users\hp\SGU_HackX\PhishLens\backend\app\services\scoring_service.py"
with open(path, "r", encoding="utf-8") as f:
    c = f.read()

bad_block = """    # Proactive zero-day phishing override:
    # When a domain clearly combines brand typosquatting with credential lures (combosquatting),
    # classify it directly as DANGEROUS (>= 75) to protect users before victim reports arrive.
    if features.typosquat_target and features.suspicious_keywords:
        raw_score = max(raw_score, 78)

    # Proactive zero-day phishing override:
    # When a domain clearly combines brand typosquatting with credential lures (combosquatting),
    # classify it directly as DANGEROUS (>= 75) to protect users before victim reports arrive.
    if features.typosquat_target and features.suspicious_keywords:
        raw_score = max(raw_score, 78)"""

good_block = """    # Proactive zero-day phishing override:
    # When a domain clearly combines brand typosquatting with credential lures (combosquatting),
    # classify it directly as DANGEROUS (>= 75) to protect users before victim reports arrive.
    if url_features.typosquat_target and url_features.suspicious_keywords:
        raw_score = max(raw_score, 78)"""

c = c.replace(bad_block, good_block)

with open(path, "w", encoding="utf-8") as f:
    f.write(c)
print("scoring_service.py updated with url_features fix!")
