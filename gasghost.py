import requests
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import os

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")

def get_gas_data(days=3):
    print("Fetching gas price data...")
    gas_prices = []

    for i in range(days):
        target_day = datetime.utcnow() - timedelta(days=i)
        timestamp = int(target_day.replace(hour=0, minute=0, second=0).timestamp())
        url = f"https://api.etherscan.io/api?module=block&action=getblocknobytime&timestamp={timestamp}&closest=before&apikey={ETHERSCAN_API_KEY}"
        response = requests.get(url).json()

        block_number = int(response['result'])
        for j in range(24):
            block = block_number + j * 150
            gas_url = f"https://api.etherscan.io/api?module=proxy&action=eth_getBlockByNumber&tag={hex(block)}&boolean=true&apikey={ETHERSCAN_API_KEY}"
            gas_res = requests.get(gas_url).json()
            if 'result' in gas_res and gas_res['result']:
                gas_price = int(gas_res['result']['baseFeePerGas'], 16) / 1e9
                gas_prices.append({'hour': j, 'gas': gas_price})

    return pd.DataFrame(gas_prices)

def analyze_and_plot(df):
    hourly_avg = df.groupby('hour').mean()
    best_hour = hourly_avg['gas'].idxmin()
    print(f"📉 Cheapest gas hour: {best_hour}:00 UTC")
    hourly_avg.plot(kind='bar', legend=False, title='Average Gas Price by Hour (Gwei)')
    plt.xlabel("Hour (UTC)")
    plt.ylabel("Gas Price (Gwei)")
    plt.tight_layout()
    plt.savefig("gas_price_analysis.png")
    print("📊 Saved plot to gas_price_analysis.png")

if __name__ == "__main__":
    df = get_gas_data()
    analyze_and_plot(df)
