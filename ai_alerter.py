import os
import json
import requests
from openai import OpenAI
from google import genai
from dotenv import load_dotenv

load_dotenv()

# Configure NVIDIA NIM (Watchdog)
nvidia_api_key = os.getenv("NVIDIA_API_KEY")
if nvidia_api_key and nvidia_api_key != "your_nvidia_nim_api_key_here":
    nim_client = OpenAI(
        base_url="https://integrate.api.nvidia.com/v1",
        api_key=nvidia_api_key
    )
else:
    nim_client = None

# Configure Gemini (Strategist)
gemini_api_key = os.getenv("GEMINI_API_KEY")
if gemini_api_key and gemini_api_key != "your_gemini_api_key_here":
    gemini_client = genai.Client(api_key=gemini_api_key)
else:
    gemini_client = None

def analyze_suspicious_query(query):
    """
    Two-tier AI analysis of the suspicious SQL query.
    1. NIM (Watchdog): Fast JSON extraction of threat details.
    2. Gemini (Strategist): Deep reasoning and human-readable explanation.
    """
    print(f"\n[Watchdog] 🐕 Starting rapid analysis on suspicious query...")
    
    if not nim_client:
        print("[!] Warning: NVIDIA_API_KEY is missing. Mocking Watchdog output for demonstration.")
        threat_data = {"threat": "Critical", "type": "SQL Injection", "target": "vault_secrets"}
    else:
        # --- Tier 1: The Watchdog (NVIDIA NIM) ---
        try:
            completion = nim_client.chat.completions.create(
                model="meta/llama-3.1-8b-instruct",
                messages=[
                    {"role": "system", "content": "You are a fast, tactical security watchdog. Parse the following SQL query that tripped a honeypot database table named 'vault_secrets'. Output exactly a JSON object (and nothing else) with the following keys: 'threat' (Low/Medium/High/Critical), 'type' (e.g. SQL Injection, Direct Query), 'target' (the table or data targeted)."},
                    {"role": "user", "content": f"Query: {query}"}
                ],
                temperature=0.1,
                max_tokens=150,
            )
            
            watchdog_response = completion.choices[0].message.content.strip()
            # Clean up in case the model added markdown blocks
            if watchdog_response.startswith('```json'):
                watchdog_response = watchdog_response[7:-3]
            elif watchdog_response.startswith('```'):
                watchdog_response = watchdog_response[3:-3]
                
            threat_data = json.loads(watchdog_response)
            print(f"[Watchdog] ✅ Threat identified. JSON payload generated:\n{json.dumps(threat_data, indent=2)}\n")
            
            # --- SEND INSTANT PHONE ALERT ---
            topic = "digital_tripwire_7a9f21"
            message = f"🚨 SECURITY BREACH DETECTED 🚨\nThreat Level: {threat_data.get('threat', 'Unknown')}\nType: {threat_data.get('type', 'Unknown')}\nTarget: {threat_data.get('target', 'Unknown')}\n\nSystem has been automatically locked down."
            try:
                requests.post(f"https://ntfy.sh/{topic}", data=message.encode('utf-8'), headers={"Title": "Database Honeypot Alert!", "Priority": "urgent", "Tags": "rotating_light,skull"})
                print(f"[Phone Alert] ✅ Push notification sent to ntfy.sh/{topic}\n")
            except Exception as e:
                print(f"[Phone Alert Error] Failed to send push notification: {e}\n")
            
        except Exception as e:
            print(f"[Watchdog Error]: Failed to parse query via NIM: {e}")
            threat_data = {"threat": "Unknown", "type": "Unknown", "target": "vault_secrets", "error": str(e)}

    # --- Tier 2: The Strategist (Google Gemini) ---
    print(f"[Strategist] 🧠 Handing over threat data to Strategist for deep reasoning...")
    
    if not gemini_client:
        print("[!] Warning: GEMINI_API_KEY is missing. Cannot generate response.")
        return

    try:
        prompt = f"""
        You are 'The Strategist', an expert cybersecurity AI for small businesses.
        An attacker has just tripped our 'Digital Tripwire' honeypot database table.
        
        The lightweight Watchdog AI extracted this threat profile:
        {json.dumps(threat_data, indent=2)}
        
        The raw SQL query executed by the attacker was:
        {query}
        
        Your job:
        1. Write an EMERGENCY ALERT for a non-technical small business owner. It must be empathetic, plain-English, and clearly explain what the attacker was trying to steal (without technical jargon).
        2. Provide actionable steps the owner should take immediately to lock down the system.
        3. Provide the exact Python code snippet or configuration change needed to patch this vulnerability (assuming this was an SQL injection in a Flask application via user input).
        
        Format the response nicely with headings.
        """
        response = gemini_client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        
        print("\n" + "="*70)
        print("🚨 EMERGENCY STRATEGIST ALERT 🚨")
        print("="*70)
        print(response.text)
        print("="*70 + "\n")
        
    except Exception as e:
        print(f"[Strategist Error]: Failed to generate response via Gemini: {e}")
