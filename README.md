# WP-login-security

Drop-in WordPress mu-plugins that replace legacy MD5/phpass password hashes with PHP native hashing. Old hashes are migrated automatically the next time each user logs in.

> Install **one** plugin only. Both override the same pluggable functions.

## Plugins

### Bcrypt.php

- Hashes with `PASSWORD_DEFAULT` (bcrypt).
- CPU-bound: slows down brute-force attempts with deliberate computation.
- Works on almost every PHP server.

### Argon2id.php

- Hashes with `PASSWORD_ARGON2ID` and falls back to bcrypt if the server doesn't support it.
- CPU- and memory-bound (64 MB RAM, 4 passes, 2 threads per hash), which neutralises GPU cracking rigs.
- Tune the cost settings in `mu_argon2id_options()`.

## How it works

1. `wp_hash_password()` creates every new hash with the native algorithm.
2. `wp_check_password()` checks native hashes with `password_verify()` and legacy hashes with phpass.
3. When a user logs in successfully with a legacy or outdated hash, it is rehashed and saved.
4. Rehashing only happens for the user's main login password, never for Application Passwords.

## Installation

1. Copy **either** `Bcrypt.php` **or** `Argon2id.php` to `/wp-content/mu-plugins/`.
2. Nothing to activate. mu-plugins load automatically.

## Requirements

- PHP 7.4+ (Argon2id needs PHP compiled with Argon2 support)
- WordPress below 6.8. From 6.8, core uses bcrypt natively and these overrides should not be used.
