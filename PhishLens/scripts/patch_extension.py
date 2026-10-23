path = r"c:\Users\hp\SGU_HackX\PhishLens\extension\src\popup\Popup.tsx"
with open(path, "r", encoding="utf-8") as f:
    c = f.read()

target = "  function openOptionsPage() {\n    void browser.runtime.openOptionsPage();\n  }"
replacement = """  function openOptionsPage() {\n    void browser.runtime.openOptionsPage();\n  }\n\n  function openDashboard() {\n    void browser.tabs.create({ url: "http://localhost:5173" });\n  }"""
c = c.replace(target, replacement)

header_target = """        <div className="header-actions">
          <button className="tool-button" type="button" aria-label="Open settings" onClick={openOptionsPage}>"""
header_replacement = """        <div className="header-actions">
          <button className="tool-button" type="button" aria-label="Open Dashboard" onClick={openDashboard} style={{ background: "#2563eb", color: "#ffffff", fontWeight: 600 }}>
            Dashboard ↗
          </button>
          <button className="tool-button" type="button" aria-label="Open settings" onClick={openOptionsPage}>"""
c = c.replace(header_target, header_replacement)

with open(path, "w", encoding="utf-8") as f:
    f.write(c)
print("Popup.tsx patched successfully!")
