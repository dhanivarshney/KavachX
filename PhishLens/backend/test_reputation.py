import google.generativeai as genai
import os
import json
from dotenv import load_dotenv

load_dotenv('c:/Users/hp/SGU_HackX/PhishLens/backend/.env')
api_key = os.getenv('GEMINI_API_KEY')
if not api_key:
    with open('c:/Users/hp/SGU_HackX/PhishLens/backend/app/routers/explain.py') as f:
        for line in f:
            if 'AIzaSy' in line:
                api_key = line.split('"')[1]
                break

genai.configure(api_key=api_key)
model = genai.GenerativeModel('gemini-2.0-flash')

for test_domain in ['paypal.com', 'paypa1-security-verification.com']:
    prompt = f'''You are a consumer trust & reputation analyst. Provide the public consumer reputation and Trustpilot standing for the domain: "{test_domain}".
Return strictly valid JSON with no markdown formatting:
{{
  "domain": "{test_domain}",
  "trust_score": float,
  "star_rating": int,
  "total_reviews": str,
  "status": "verified" or "unverified" or "suspicious",
  "top_reviews": [
    {{"author": "Customer", "rating": int, "comment": "...", "date": "Recent"}}
  ],
  "community_verdict": "2 sentence explanation for regular users",
  "trustpilot_url": "https://www.trustpilot.com/review/{test_domain}"
}}'''
    resp = model.generate_content(prompt)
    print(f"=== DOMAIN: {test_domain} ===")
    print(resp.text.strip())
