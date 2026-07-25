"""
Setup:
  export BOT_TOKEN="123456:ABC..."
  export ALLOWED_USER_ID="7390266725"
  python3 bot.py

Cryptography:
  Key derivation : PBKDF2-HMAC-SHA256, 200000 iterations, random 16 byte salt
  Encryption     : HMAC-SHA256 based stream cipher (CTR mode keystream)
  Authentication : HMAC-SHA256 encrypt-then-MAC, constant time verification
  Output format  : urlsafe base64 of salt(16) + ciphertext + tag(32)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


FALLBACK_BOT_TOKEN = "PUT-YOUR-BOT-TOKEN-HERE"
FALLBACK_ALLOWED_USER_ID = 0  # for example 0123245678

BOT_TOKEN = os.environ.get("BOT_TOKEN", FALLBACK_BOT_TOKEN).strip()

try:
    ALLOWED_USER_ID = int(os.environ.get("ALLOWED_USER_ID", str(FALLBACK_ALLOWED_USER_ID)))
except ValueError:
    ALLOWED_USER_ID = 0

USERS_FILE = os.path.abspath(os.environ.get("USERS_FILE", "users.json"))

API_BASE = "https://api.telegram.org/bot"
LONG_POLL_TIMEOUT = 30
REQUEST_TIMEOUT = LONG_POLL_TIMEOUT + 15

KDF_ITERATIONS = 200000
SALT_SIZE = 16
TAG_SIZE = 32

MIN_PASSWORD_LENGTH = 4
MAX_PASSWORD_LENGTH = 128
MAX_PLAINTEXT_LENGTH = 3000

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
)
logger = logging.getLogger("crypto-bot")

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            logger.warning("users.json has an unexpected structure. Ignoring it.")
            return {}
        return data
    except (OSError, ValueError) as error:
        logger.error("Failed to read %s: %s", USERS_FILE, error)
        return {}


def save_users(data):
    temp_file = USERS_FILE + ".tmp"
    try:
        directory = os.path.dirname(USERS_FILE)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(temp_file, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
        os.replace(temp_file, USERS_FILE)
        try:
            os.chmod(USERS_FILE, 0o600)
        except OSError:
            pass
        return True
    except OSError as error:
        logger.error("Failed to write %s: %s", USERS_FILE, error)
        return False


def get_password(user_id):
    record = load_users().get(str(user_id))
    if isinstance(record, dict):
        password = record.get("password")
        if isinstance(password, str) and password:
            return password
    return None


def set_password(user_id, password):
    data = load_users()
    record = data.get(str(user_id))
    if not isinstance(record, dict):
        record = {}
    record["password"] = password
    data[str(user_id)] = record
    return save_users(data)

def derive_keys(password, salt):
    material = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, KDF_ITERATIONS, dklen=64
    )
    return material[:32], material[32:]

def keystream(enc_key, length):
    output = bytearray()
    counter = 0
    while len(output) < length:
        block = hmac.new(enc_key, struct.pack(">Q", counter), hashlib.sha256).digest()
        output.extend(block)
        counter += 1
    return bytes(output[:length])


def xor_bytes(data, stream):
    return bytes(a ^ b for a, b in zip(data, stream))

def encrypt_text(plaintext, password):
    salt = secrets.token_bytes(SALT_SIZE)
    enc_key, mac_key = derive_keys(password, salt)
    data = plaintext.encode("utf-8")
    ciphertext = xor_bytes(data, keystream(enc_key, len(data)))
    tag = hmac.new(mac_key, salt + ciphertext, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(salt + ciphertext + tag).decode("ascii")

def decrypt_text(token, password):
    cleaned = "".join(token.split())
    padding = "=" * (-len(cleaned) % 4)
    try:
        raw = base64.urlsafe_b64decode(cleaned + padding)
    except Exception:
        raise ValueError("Invalid ciphertext encoding.")

    if len(raw) < SALT_SIZE + TAG_SIZE:
        raise ValueError("Ciphertext is too short.")

    salt = raw[:SALT_SIZE]
    ciphertext = raw[SALT_SIZE:-TAG_SIZE]
    tag = raw[-TAG_SIZE:]

    enc_key, mac_key = derive_keys(password, salt)
    expected = hmac.new(mac_key, salt + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, tag):
        raise ValueError("Invalid ciphertext or password.")

    try:
        return xor_bytes(ciphertext, keystream(enc_key, len(ciphertext))).decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Invalid ciphertext or password.")

def api_call(method, params=None, timeout=REQUEST_TIMEOUT):
    url = API_BASE + BOT_TOKEN + "/" + method
    payload = json.dumps(params or {}).encode("utf-8")
    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")
        logger.error("HTTP %s on %s: %s", error.code, method, body)
        return None
    except Exception as error:
        logger.error("Request %s failed: %s", method, error)
        return None


def send_message(chat_id, text, markdown=False):
    params = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
    if markdown:
        params["parse_mode"] = "MarkdownV2"
    return api_call("sendMessage", params)


MARKDOWN_SPECIALS = "_*[]()~`>#+-=|{}.!\\"


def escape_markdown(text):
    return "".join("\\" + char if char in MARKDOWN_SPECIALS else char for char in text)


def escape_code(text):
    """Escape text placed inside a MarkdownV2 code entity."""
    return text.replace("\\", "\\\\").replace("`", "\\`")


def send_copyable(chat_id, title, body):
    """Send a message whose body is a tap-to-copy code block."""
    text = escape_markdown(title) + "\n```\n" + escape_code(body) + "\n```"
    result = send_message(chat_id, text, markdown=True)
    if not result or not result.get("ok"):
        send_message(chat_id, title + "\n\n" + body)

HELP_TEXT = (
    "Available commands:\n"
    "/start - show this information\n"
    "/password - view or change your password\n"
    "/setpassword - set a new password\n"
    "/decrypt <message> - decrypt an encrypted message\n"
    "/cancel - cancel the current operation\n\n"
    "Send any plain text message and it will be encrypted automatically."
)

ASK_PASSWORD_TEXT = (
    "No password is set yet.\n"
    "Send a new password now. It will be used to encrypt and decrypt your messages.\n"
    "Length: " + str(MIN_PASSWORD_LENGTH) + " to " + str(MAX_PASSWORD_LENGTH) + " characters."
)

STATES = {}
STATE_WAITING_PASSWORD = "waiting_for_new_password"

def handle_password_input(chat_id, user_id, text):
    new_password = text.strip()

    if new_password.startswith("/"):
        send_message(chat_id, "A password cannot start with a slash. Send another one.")
        return

    if not (MIN_PASSWORD_LENGTH <= len(new_password) <= MAX_PASSWORD_LENGTH):
        send_message(
            chat_id,
            "Invalid length. Use "
            + str(MIN_PASSWORD_LENGTH)
            + " to "
            + str(MAX_PASSWORD_LENGTH)
            + " characters.",
        )
        return

    if not set_password(user_id, new_password):
        send_message(chat_id, "Storage error. The password was not saved. Try again later.")
        return

    STATES.pop(user_id, None)
    send_message(
        chat_id,
        "Password saved.\n\n"
        "From now on every plain text message you send will be encrypted automatically.\n\n"
        + HELP_TEXT,
    )


def handle_message(message):
    chat = message.get("chat") or {}
    sender = message.get("from") or {}
    chat_id = chat.get("id")
    user_id = sender.get("id")
    text = message.get("text")

    if chat_id is None or user_id is None:
        return

    if user_id != ALLOWED_USER_ID:
        logger.warning("Unauthorized access attempt from user_id=%s", user_id)
        send_message(chat_id, "Access denied.")
        return

    if not text:
        send_message(chat_id, "Unsupported input. Send plain text or use /help.")
        return

    text = text.strip()
    command = ""
    argument = ""
    if text.startswith("/"):
        parts = text.split(None, 1)
        command = parts[0].split("@", 1)[0].lower()
        argument = parts[1] if len(parts) > 1 else ""

    # Active FSM state
    if STATES.get(user_id) == STATE_WAITING_PASSWORD and command != "/cancel":
        handle_password_input(chat_id, user_id, text)
        return

    if command == "/cancel":
        if STATES.pop(user_id, None) is None:
            send_message(chat_id, "Nothing to cancel.")
        else:
            send_message(chat_id, "Operation cancelled.")
        return

    if command == "/start":
        if get_password(user_id) is None:
            STATES[user_id] = STATE_WAITING_PASSWORD
            send_message(chat_id, "Encryption bot ready.\n\n" + ASK_PASSWORD_TEXT)
        else:
            send_message(
                chat_id, "Encryption bot ready. A password is already set.\n\n" + HELP_TEXT
            )
        return

    if command == "/help":
        send_message(chat_id, HELP_TEXT)
        return

    if command == "/password":
        password = get_password(user_id)
        if password is None:
            STATES[user_id] = STATE_WAITING_PASSWORD
            send_message(chat_id, ASK_PASSWORD_TEXT)
            return
        send_message(
            chat_id,
            "Current password: ||"
            + escape_markdown(password)
            + "||\n\n"
            + escape_markdown(
                "Tap the hidden text above to reveal it.\n"
                "To change the password, send /setpassword and then the new password."
            ),
            markdown=True,
        )
        return

    if command == "/setpassword":
        STATES[user_id] = STATE_WAITING_PASSWORD
        send_message(
            chat_id,
            "Send the new password.\n"
            "Length: "
            + str(MIN_PASSWORD_LENGTH)
            + " to "
            + str(MAX_PASSWORD_LENGTH)
            + " characters.\n"
            "Note: text encrypted with the previous password cannot be decrypted afterwards.\n"
            "Send /cancel to abort.",
        )
        return

    if command == "/decrypt":
        password = get_password(user_id)
        if password is None:
            send_message(chat_id, "No password is set. Use /password to set one first.")
            return
        if not argument.strip():
            send_message(chat_id, "Usage: /decrypt <encrypted message>")
            return
        try:
            plaintext = decrypt_text(argument, password)
        except ValueError:
            send_message(chat_id, "Decryption failed. Invalid ciphertext or password.")
            return
        send_copyable(chat_id, "Decrypted message:", plaintext)
        return

    if command:
        send_message(chat_id, "Unknown command. Use /help.")
        return

    password = get_password(user_id)
    if password is None:
        STATES[user_id] = STATE_WAITING_PASSWORD
        send_message(chat_id, "No password is set. " + ASK_PASSWORD_TEXT)
        return

    if len(text) > MAX_PLAINTEXT_LENGTH:
        send_message(
            chat_id,
            "Message is too long. The limit is " + str(MAX_PLAINTEXT_LENGTH) + " characters.",
        )
        return

    try:
        ciphertext = encrypt_text(text, password)
    except Exception as error:
        logger.error("Encryption failed: %s", error)
        send_message(chat_id, "Encryption failed. Try again.")
        return

    send_copyable(chat_id, "Encrypted message:", ciphertext)

def main():
    if not BOT_TOKEN or BOT_TOKEN == "PUT-YOUR-BOT-TOKEN-HERE":
        logger.error("BOT_TOKEN is not configured. Set the BOT_TOKEN environment variable.")
        sys.exit(1)

    if ALLOWED_USER_ID <= 0:
        logger.error(
            "ALLOWED_USER_ID is not configured. Set the ALLOWED_USER_ID environment variable."
        )
        sys.exit(1)

    me = api_call("getMe", {}, timeout=20)
    if not me or not me.get("ok"):
        logger.error("Cannot reach the Telegram API or the token is invalid.")
        sys.exit(1)

    logger.info("Authorized as @%s", me["result"].get("username"))
    logger.info("Storage file: %s", USERS_FILE)
    logger.info("Authorized user id: %s", ALLOWED_USER_ID)

    api_call("deleteWebhook", {"drop_pending_updates": True}, timeout=20)

    offset = None
    logger.info("Bot started.")

    while True:
        params = {"timeout": LONG_POLL_TIMEOUT, "allowed_updates": ["message"]}
        if offset is not None:
            params["offset"] = offset

        response = api_call("getUpdates", params)
        if not response or not response.get("ok"):
            time.sleep(3)
            continue

        for update in response.get("result", []):
            offset = update["update_id"] + 1
            message = update.get("message")
            if not message:
                continue
            try:
                handle_message(message)
            except Exception as error:
                logger.error("Handler error: %s", error)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Bot stopped.")
