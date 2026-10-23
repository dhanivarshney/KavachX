path = r"c:\Users\hp\SGU_HackX\PhishLens\extension\src\popup\Popup.tsx"
with open(path, "r", encoding="utf-8") as f:
    c = f.read()

c = c.replace("<h1>Page risk</h1>", "<h1>Website Safety</h1>")
c = c.replace("<h2>Signals</h2>", "<h2>Safety Checks</h2>")
c = c.replace("Mark as phishing", "Report as Scam")
c = c.replace("Copy report", "Copy Safety Summary")

with open(path, "w", encoding="utf-8") as f:
    f.write(c)
print("Popup.tsx updated with friendly text!")
