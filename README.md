# Password Manager - Stenvard

A secure password manager built with Django featuring per-user encryption and Argon2id key derivation.

## Features
- Secure user authentication with custom login/registration
- Encrypted password storage using Fernet symmetric encryption
- Per-user encryption keys derived from passwords using Argon2id
- Session-based key management for credential access
- Individual credential viewing with real-time decryption

## Status
**Core functionality complete** - users can securely store and retrieve encrypted passwords.

**Account recovery functionality** - complete** - users can reset their account if they lose their password or in the event of encryption issues.

## Tech Stack
- Python 3.13 / Django 5.2.5
- SQLite (development database)
- cryptography library (Fernet + Argon2id)

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
This is an educational project demonstrating Django security patterns and cryptographic best practices.
Not intended for production use without additional security hardening, styling tweaks and testing.

I'm still learning as I continue to build and develop these projects in-between Uni study, so certain elements may be incomplete or not be implemented in the most optimal fashion. I am fully open to feedback and pointers so please comment and let me know your thoughts, observations or critique. 