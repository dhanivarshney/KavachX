import urllib.request
import urllib.parse
import re

def check_trustpilot_via_search(domain: str):
    query = urllib.parse.quote(f'site:trustpilot.com/review "{domain}"')
    url = f"https://html.duckduckgo.com/html/?q={query}"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            html = resp.read().decode('utf-8', errors='ignore')
            snippets = re.findall(r'<a class="result__snippet"[^>]*>(.*?)</a>', html, re.DOTALL)
            results = []
            for s in snippets:
                clean = re.sub(r'<[^>]+>', '', s).strip()
                results.append(clean)
            return results
    except Exception as e:
        return [f"Error: {e}"]

print("=== PAYPAL ===")
for res in check_trustpilot_via_search("paypal.com")[:2]:
    print("-", res)

print("\n=== FAKE PAYPAL ===")
fake_res = check_trustpilot_via_search("paypa1-security-verification.com")
print("Found results:", len(fake_res))
if fake_res:
    for res in fake_res[:2]:
        print("-", res)
