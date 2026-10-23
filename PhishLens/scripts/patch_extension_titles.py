path = r"c:\Users\hp\SGU_HackX\PhishLens\extension\src\utils\signal-categories.ts"
with open(path, "r", encoding="utf-8") as f:
    c = f.read()

old_titles = """const CATEGORY_TITLES: Record<SignalCategoryId, string> = {
  url: "URL",
  dom: "Page structure",
  "threat-intel": "Threat intelligence",
  tls: "TLS",
  "domain-age": "Domain age",
  ml: "ML",
  general: "General",
};"""

new_titles = """const CATEGORY_TITLES: Record<SignalCategoryId, string> = {
  url: "Web Address Check",
  dom: "Page Content & Forms",
  "threat-intel": "Scam Blacklist Check",
  tls: "Security Lock (SSL)",
  "domain-age": "Website Age",
  ml: "AI Pattern Matcher",
  general: "General Safety",
};"""

c = c.replace(old_titles, new_titles)

with open(path, "w", encoding="utf-8") as f:
    f.write(c)
print("signal-categories.ts updated with friendly titles!")
