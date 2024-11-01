import os
import hmac
import hashlib
import discord
from discord.ext import commands
from discord import ui
from quart import Quart, request, jsonify
import aiosqlite
import asyncio
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from colorama import Fore, Style, init
import ntplib
from datetime import datetime, timezone
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
ENCRYPTION_KEY = bytes.fromhex(os.getenv("ENCRYPTION_KEY"))
STATIC_IV = bytes.fromhex(os.getenv("STATIC_IV"))
NUM_WORKERS = int(os.getenv("NUM_WORKERS", 5))

# Initialize colorama for colored terminal output
init(autoreset=True)

# Paths and database setup
script_dir = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(script_dir, "bot_data.db")

# Discord bot setup with intents
intents = discord.Intents.default()
intents.message_content = True
intents.dm_messages = True
bot = commands.Bot(command_prefix="!", intents=intents)

# Quart setup for asynchronous HTTP server
app = Quart(__name__)

# Queue for handling incoming message requests
message_queue = asyncio.Queue()

# Function to get synced UTC time from an NTP server
def get_ntp_time(ntp_server="pool.ntp.org"):
    client = ntplib.NTPClient()
    response = client.request(ntp_server, version=3)
    ntp_time = datetime.fromtimestamp(response.tx_time, timezone.utc)
    return ntp_time

# AES encryption utility functions with logging
def encrypt_data(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return base64.b64encode(encrypted_data).decode()

def decrypt_data(encrypted_data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    raw_data = base64.b64decode(encrypted_data)
    decrypted_data = unpad(cipher.decrypt(raw_data), AES.block_size)
    return decrypted_data.decode()

# Initialize the database
async def init_db():
    async with aiosqlite.connect(db_path) as db:
        await db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                token TEXT PRIMARY KEY,
                discord_id TEXT,
                secret_key TEXT
            )
        ''')
        await db.commit()

# Helper functions for managing tokens and user data
async def add_user(token, discord_id, secret_key):
    encrypted_discord_id = encrypt_data(discord_id, ENCRYPTION_KEY, STATIC_IV)
    async with aiosqlite.connect(db_path) as db:
        await db.execute("REPLACE INTO users (token, discord_id, secret_key) VALUES (?, ?, ?)",
                         (token, encrypted_discord_id, secret_key))
        await db.commit()

async def get_user_info(discord_id):
    encrypted_discord_id = encrypt_data(discord_id, ENCRYPTION_KEY, STATIC_IV)
    async with aiosqlite.connect(db_path) as db:
        async with db.execute("SELECT token, secret_key FROM users WHERE discord_id = ?", (encrypted_discord_id,)) as cursor:
            row = await cursor.fetchone()
            return row if row else (None, None)

async def delete_user_info(discord_id):
    encrypted_discord_id = encrypt_data(discord_id, ENCRYPTION_KEY, STATIC_IV)
    async with aiosqlite.connect(db_path) as db:
        await db.execute("DELETE FROM users WHERE discord_id = ?", (encrypted_discord_id,))
        await db.commit()

# Bot commands for user management with interactive buttons
class CommandButtons(ui.View):
    def __init__(self):
        super().__init__()

    @ui.button(label="Register User", style=discord.ButtonStyle.primary)
    async def register_user_button(self, interaction: discord.Interaction, button: ui.Button):
        discord_id = str(interaction.user.id)
        
        # Check if the user is already registered
        token, secret_key = await get_user_info(discord_id)
        if token and secret_key:
            # Inform the user of their existing registration
            await interaction.response.send_message(
                f"❗ You are already registered.\n**Token:** `{token}`\n**Secret Key:** `{secret_key}`",
                ephemeral=True
            )
            return
        
        # If not registered, create new token and secret key
        token = str(random.randint(10000000, 99999999))
        secret_key = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
        await add_user(token, discord_id, secret_key)
        await interaction.response.send_message(
            f"🔑 **Token and Secret Key Generated:**\n**Token:** `{token}`\n**Secret Key:** `{secret_key}`\nPlease store both in your plugin configuration.",
            ephemeral=True
        )

    @ui.button(label="Show User", style=discord.ButtonStyle.secondary)
    async def show_user_button(self, interaction: discord.Interaction, button: ui.Button):
        discord_id = str(interaction.user.id)
        token, secret_key = await get_user_info(discord_id)
        if token and secret_key:
            await interaction.response.send_message(
                f"🔍 **Your Credentials:**\n**Token:** `{token}`\n**Secret Key:** `{secret_key}`",
                ephemeral=True
            )
        else:
            await interaction.response.send_message(
                "❗ You don’t have a verified token and secret key. Use `!register_user` to generate them.",
                ephemeral=True
            )

    @ui.button(label="Remove User", style=discord.ButtonStyle.danger)
    async def remove_user_button(self, interaction: discord.Interaction, button: ui.Button):
        discord_id = str(interaction.user.id)
        await delete_user_info(discord_id)
        await interaction.response.send_message(
            "🗑️ Your credentials have been deleted. Use `!register_user` to generate new ones if needed.",
            ephemeral=True
        )

@bot.command(name="list_commands")
async def list_commands_command(ctx):
    await ctx.send("**Available Commands:**\nClick a button below to use a command:", view=CommandButtons())

@bot.event
async def on_message(message):
    if message.author != bot.user and message.content.lower() == "hello":
        await message.channel.send("Hello! Here’s a list of commands you can use:")
        await list_commands_command(message.channel)
    await bot.process_commands(message)

# Worker coroutine to process messages from the queue 
async def process_queue(worker_id):
    while True:
        # Log that the worker is waiting for a message
        print(f"{Fore.BLUE}[Worker {worker_id}] Waiting for a new message in the queue...{Style.RESET_ALL}")
        
        # Retrieve the next item in the queue
        request_data = await message_queue.get()
        print(f"{Fore.CYAN}[Worker {worker_id}] Retrieved a message from the queue: {request_data}{Style.RESET_ALL}")

        # Log individual fields of the request data for clarity
        user_token = request_data["user_token"]
        title = request_data["title"]
        text = request_data["text"]
        nonce = request_data["nonce"]
        timestamp = request_data["timestamp"]
        received_hash = request_data["hash"]
        print(f"{Fore.CYAN}[Worker {worker_id}] Message details - User Token: {user_token}, Title: '{title}', Nonce: {nonce}, Timestamp: {timestamp}{Style.RESET_ALL}")

        # Retrieve user info from the database
        async with aiosqlite.connect(db_path) as db:
            async with db.execute("SELECT discord_id, secret_key FROM users WHERE token = ?", (user_token,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    encrypted_discord_id, stored_secret_key = row
                    discord_id = decrypt_data(encrypted_discord_id, ENCRYPTION_KEY, STATIC_IV)
                    print(f"{Fore.GREEN}[Worker {worker_id}] User found - Discord ID: {discord_id}, Secret Key retrieved successfully.{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[Worker {worker_id}] No matching user found for token '{user_token}'. Dropping message.{Style.RESET_ALL}")
                    message_queue.task_done()
                    continue

        # Compute HMAC hash and verify against the received hash
        message_data = f"{user_token}{title}{text}{nonce}{timestamp}"
        computed_hash = hmac.new(stored_secret_key.encode(), message_data.encode(), hashlib.sha256).digest()
        computed_hash_base64 = base64.b64encode(computed_hash).decode()
        
        if received_hash != computed_hash_base64:
            print(f"{Fore.RED}[Worker {worker_id}] Hash mismatch! Expected: {received_hash}, Computed: {computed_hash_base64}. Dropping message.{Style.RESET_ALL}")
            message_queue.task_done()
            continue
        print(f"{Fore.GREEN}[Worker {worker_id}] Hash verified successfully.{Style.RESET_ALL}")

        # Send the message to the Discord user
        try:
            user = await bot.fetch_user(int(discord_id))
            print(f"{Fore.YELLOW}[Worker {worker_id}] Sending message to Discord user with ID {discord_id}.{Style.RESET_ALL}")
            await user.send(f"**{title}**\n{text}")
            print(f"{Fore.GREEN}[Worker {worker_id}] Message sent successfully to Discord user {discord_id}.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[Worker {worker_id}] [Error] Failed to send message to user {discord_id}: {e}{Style.RESET_ALL}")

        # Mark the message as processed
        message_queue.task_done()
        print(f"{Fore.MAGENTA}[Worker {worker_id}] Finished processing message and marked it as done.{Style.RESET_ALL}")

# Start multiple workers for processing the message queue
async def start_workers():
    tasks = [process_queue(i) for i in range(NUM_WORKERS)]
    await asyncio.gather(*tasks)

# Route for receiving messages
@app.route("/send", methods=["POST"])
async def send_message():
    data = await request.get_json()
    await message_queue.put(data)
    print(f"Message queued for delivery: {data}")
    return jsonify({"message": "Message queued for delivery"}), 200

async def start_bot():
    await init_db()
    await asyncio.gather(bot.start(DISCORD_TOKEN), app.run_task(port=5050), start_workers())

asyncio.run(start_bot())
