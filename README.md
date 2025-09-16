# Password Manager

A secure password manager built with **Django** featuring per-user encryption and Argon2id key derivation.

## Features
- Secure user authentication with custom login/registration
- Encrypted password storage using Fernet symmetric encryption
- Per-user encryption keys derived from passwords using Argon2id
- Session-based key management for credential access
- Individual credential viewing with real-time decryption

## Status
**Core functionality complete** — users can securely store and retrieve encrypted passwords.

## Tech Stack
- Python 3.13 / Django 5.2.5
- SQLite (development database)
- cryptography library (Fernet + Argon2id)
- Custom UserProfile model for salt storage

## Security Architecture
- **Key Derivation**: Argon2id with per-user salts
- **Encryption**: Fernet symmetric encryption for password storage
- **Session Management**: Base64-encoded keys stored in Django sessions
- **User Isolation**: All credentials filtered by authenticated user

## Roadmap
- [x] User registration & login
- [x] Store & retrieve encrypted passwords
- [x] Per-user encryption keys
- [x] Individual credential viewing
- [x] Edit/delete credential functionality
- [x] Password visibility toggles
- [ ] UI styling and responsive design
- [ ] Deployment configuration

## Notes
This is an **educational project** demonstrating Django security patterns and cryptographic best practices.
Not intended for production use without additional security hardening.  
