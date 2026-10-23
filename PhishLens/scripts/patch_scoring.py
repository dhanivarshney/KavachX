import re

path = r"c:\Users\hp\SGU_HackX\PhishLens\backend\app\services\scoring_service.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Change num_hyphens > 2 to num_hyphens >= 2
content = content.replace("if features.num_hyphens > 2:", "if features.num_hyphens >= 2:")

# Add combosquatting boost after typosquatting
old_typosquat_block = """    if features.typosquat_target:
        if features.typosquat_is_homograph:
            score += 16
            reasons.append(
                f"Domain uses look-alike Unicode characters resembling {features.typosquat_target} "
                "(homograph attack)"
            )
        else:
            score += 14
            reasons.append(f"Domain closely resembles {features.typosquat_target} (possible typosquatting)")"""

new_typosquat_block = """    if features.typosquat_target:
        if features.typosquat_is_homograph:
            score += 16
            reasons.append(
                f"Domain uses look-alike Unicode characters resembling {features.typosquat_target} "
                "(homograph attack)"
            )
        else:
            score += 14
            reasons.append(f"Domain closely resembles {features.typosquat_target} (possible typosquatting)")

        if features.suspicious_keywords:
            score += 10
            reasons.append(
                f"Deceptive combosquatting: impersonates {features.typosquat_target} alongside credential lure keywords"
            )"""

content = content.replace(old_typosquat_block, new_typosquat_block)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("scoring_service.py patched successfully!")
