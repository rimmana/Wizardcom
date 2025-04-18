### Repository: CryptoTap
# Purpose: A Python utility that detects unusual wallet behavior ("wallet tapping") by analyzing wallet transaction patterns for anomalies—potentially catching draining scripts, compromised wallets, or automated attacks early.

# Filename: cryptotap.py
import requests
import time
from datetime import datetime, timedelta
import json

ETHERSCAN_API_KEY = 'YOUR_ETHERSCAN_API_KEY'
ETHERSCAN_API_URL = 'https://api.etherscan.io/api'


def get_wallet_transactions(address, start_block=0):
    url = f"{ETHERSCAN_API_URL}?module=account&action=txlist&address={address}&startblock={start_block}&endblock=99999999&sort=desc&apikey={ETHERSCAN_API_KEY}"
    response = requests.get(url)
    data = response.json()
    if data['status'] != '1':
        return []
    return data['result']


def detect_wallet_tapping(transactions, threshold=5, time_window_minutes=3):
    timestamps = [int(tx['timeStamp']) for tx in transactions]
    timestamps.sort(reverse=True)
    
    window = timedelta(minutes=time_window_minutes)
    count = 0
    for i in range(len(timestamps)):
        count = 1
        for j in range(i + 1, len(timestamps)):
            if datetime.utcfromtimestamp(timestamps[i]) - datetime.utcfromtimestamp(timestamps[j]) <= window:
                count += 1
            else:
                break
        if count >= threshold:
            return True, timestamps[i: i+count]
    return False, []


def monitor_wallet(address):
    print(f"\n🔍 Monitoring wallet: {address}")
    txs = get_wallet_transactions(address)
    is_tapped, relevant = detect_wallet_tapping(txs)
    if is_tapped:
        print(f"⚠️ Wallet {address} might be compromised! High activity detected:")
        for ts in relevant:
            print("-", datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"))
    else:
        print("✅ No suspicious activity detected.")


if __name__ == "__main__":
    wallet_address = input("Enter wallet address to monitor: ").strip()
    monitor_wallet(wallet_address)
