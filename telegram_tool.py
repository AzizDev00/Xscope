from telethon.sync import TelegramClient
from telethon.sessions import StringSession
from telethon.events import NewMessage
import os
import json
import re
import asyncio

CONFIG_FILE = "telegram_config.json"
SESSION_FILE = "session.txt"

def load_api_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
            return data["api_id"], data["api_hash"]
    else:
        print("\n[+] Enter your Telegram API credentials:")
        api_id = int(input("API ID: "))
        api_hash = input("API HASH: ").strip()
        with open(CONFIG_FILE, "w") as f:
            json.dump({"api_id": api_id, "api_hash": api_hash}, f)
        return api_id, api_hash

def create_session():
    api_id, api_hash = load_api_config()
    phone = input("Enter phone number (with +): ")

    client = TelegramClient(StringSession(), api_id, api_hash)
    with client:
        client.send_code_request(phone)
        code = input("Enter the code you received: ")
        client.sign_in(phone, code)
        session_string = client.session.save()
        with open(SESSION_FILE, "w") as f:
            f.write(session_string)
        print(f"\n[✓] Session saved to {SESSION_FILE}")

def sniff_code():
    if not os.path.exists(SESSION_FILE):
        print("[!] No session file found. Run option 1 first.")
        return

    api_id, api_hash = load_api_config()
    with open(SESSION_FILE, "r") as f:
        session = StringSession(f.read())

    client = TelegramClient(session, api_id, api_hash)

    @client.on(NewMessage(from_users=777000))
    async def handler(event):
        msg = event.message.message
        match = re.search(r"code is (\d+)", msg)
        if match:
            print(f"\n[+] Telegram Code Received: {match.group(1)}")
            await client.disconnect()

    print("[*] Listening for code message from Telegram (user 777000)...")
    client.start()
    client.run_until_disconnected()

def run():
    print("\n=== Telegram Tool ===")
    print("  1. Create .session file")
    print("  2. Sniff Telegram code (from 777000)")
    choice = input(">>> ").strip()
    if choice == "1":
        create_session()
    elif choice == "2":
        sniff_code()
    else:
        print("[!] Invalid choice.")
