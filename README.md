# tg-cipher-bot

Single-file Telegram bot for personal text encryption. Python 3, standard library only, no external dependencies.

Send the bot any plain text and it replies with an encrypted, tap-to-copy string. Send /decrypt <text> and it gives the message back. Only one hardcoded Telegram account can talk to it; everyone else gets Access denied.

---

## Why it exists

I wanted a private cipher tool running on hardware I control, so it lives on an old jailbroken iPhone. That environment ships an outdated Python and cannot build packages that need a Rust or C toolchain, which rules out aiogram, cryptography etc.. So the whole thing is one file on top of the standard library: urllib for the Telegram API, hashlib and hmac for the crypto.

It runs anywhere Python 3.6+ runs. No pip installs.

---

## Requirements

- Python 3.6 or newer
- A bot token from @BotFather
- Your numeric Telegram user ID

---

## Setup

bash git clone <https://github.com/><your-name>/tg-cipher-bot.git cd tg-cipher-bot  export BOT_TOKEN=123456789:AAHexampleTokenFromBotFather export ALLOWED_USER_ID=123456789  python3 bot.py 

or

python FALLBACK_BOT_TOKEN = "123456789:AAHexampleTokenFromBotFather" FALLBACK_ALLOWED_USER_ID = 123456789 

Optional: set USERS_FILE to move the storage file somewhere else.

### Keeping it alive

bash tmux new -s bot 

---

## Usage

Changing the password does not re-encrypt anything. Text encrypted with the old password can no longer be decrypted, so keep the old one if you still need it.

---

## Cryptography

| Stage | Implementation |
| --- | --- |
| Key derivation | PBKDF2-HMAC-SHA256, 200000 iterations, random 16 byte salt, 64 bytes of output split into an encryption key and a MAC key |
| Encryption | HMAC-SHA256 keystream in counter mode, XORed with the plaintext |
| Authentication | Encrypt-then-MAC with HMAC-SHA256, verified in constant time |
| Output | urlsafe base64 of salt(16) + ciphertext + tag(32) |

---

## Security notes

Read this before trusting the bot with anything that matters.

- The password is stored in plain text in users.json. That is a deliberate trade-off: the bot can show you the password on demand, which is impossible with a hash. Anyone with read access to that file owns your ciphertexts.
- The construction is sound but non-standard. HMAC-based CTR plus encrypt-then-MAC is a well understood pattern, but AES-GCM from a reviewed library is the better default whenever you can install one. This exists because the target device cannot.
- Messages travel through Telegram. Plaintext you type reaches Telegram servers before the bot encrypts it. This protects text at rest, wherever you paste the ciphertext afterwards; it is not end-to-end encryption of the chat itself.


## License

MIT# tg-cipher-bot

Single-file Telegram bot for personal text encryption. Python 3, standard library only, no external dependencies.

Send the bot any plain text and it replies with an encrypted, tap-to-copy string. Send /decrypt <text> and it gives the message back. Only one hardcoded Telegram account can talk to it; everyone else gets Access denied.

---

## Why it exists

I wanted a private cipher tool running on hardware I control, so it lives on an old jailbroken iPhone. That environment ships an outdated Python and cannot build packages that need a Rust or C toolchain, which rules out aiogram, cryptography and friends. So the whole thing is one file on top of the standard library: urllib for the Telegram API, hashlib and hmac for the crypto.

It runs anywhere Python 3.6+ runs. No pip installs.

---

## Requirements

- Python 3.6 or newer
- A bot token from @BotFather
- Your numeric Telegram user ID

---

## Setup

bash git clone <https://github.com/><your-name>/tg-cipher-bot.git cd tg-cipher-bot  export BOT_TOKEN=123456789:AAHexampleTokenFromBotFather export ALLOWED_USER_ID=123456789  python3 bot.py 

or

python FALLBACK_BOT_TOKEN = "123456789:AAHexampleTokenFromBotFather" FALLBACK_ALLOWED_USER_ID = 123456789 

Optional: set USERS_FILE to move the storage file somewhere else.

### Keeping it alive

bash tmux new -s bot 

---

## Usage

Changing the password does not re-encrypt anything. Text encrypted with the old password can no longer be decrypted, so keep the old one if you still need it.

---

## Cryptography

| Stage | Implementation |
| --- | --- |
| Key derivation | PBKDF2-HMAC-SHA256, 200000 iterations, random 16 byte salt, 64 bytes of output split into an encryption key and a MAC key |
| Encryption | HMAC-SHA256 keystream in counter mode, XORed with the plaintext |
| Authentication | Encrypt-then-MAC with HMAC-SHA256, verified in constant time |
| Output | urlsafe base64 of salt(16) + ciphertext + tag(32) |

---

## Security notes

Read this before trusting the bot with anything that matters.

- The password is stored in plain text in users.json. That is a deliberate trade-off: the bot can show you the password on demand, which is impossible with a hash. Anyone with read access to that file owns your ciphertexts.
- The construction is sound but non-standard. HMAC-based CTR plus encrypt-then-MAC is a well understood pattern, but AES-GCM from a reviewed library is the better default whenever you can install one. This exists because the target device cannot.
- Messages travel through Telegram. Plaintext you type reaches Telegram servers before the bot encrypts it. This protects text at rest, wherever you paste the ciphertext afterwards; it is not end-to-end encryption of the chat itself.
