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

## Tests

### Setup

```bash
composer install
```

### Run

```bash
composer test            # both plugins
composer test:bcrypt     # Bcrypt.php only
composer test:argon2id   # Argon2id.php only
```

Each test prints its steps as it runs.

### What's tested

**Both plugins**

- Opening the file directly is blocked
- New hashes are native, verify, and are uniquely salted
- Current native hash + correct password: accepted, not rehashed
- Native hash + wrong password: rejected, not rehashed
- Outdated native hash: upgraded on login
- Legacy phpass hash: accepted and migrated
- Legacy hash + wrong password: rejected, not migrated
- Application Passwords (legacy or native) never overwrite the login password
- No user ID: no lookup, no rehash
- Result passes through the `check_password` filter

**Bcrypt.php**

- Hashes are bcrypt and match `PASSWORD_DEFAULT`

**Argon2id.php**

- `mu_argon2id_options()` returns 64 MB / 4 passes / 2 threads
- Hashes are Argon2id with those options
- Current Argon2id hash is not rehashed on every login
- Argon2id hash with old settings is upgraded
- Bcrypt hash is upgraded to Argon2id

## Requirements

- PHP 7.4+ (Argon2id needs PHP compiled with Argon2 support)
- WordPress below 6.8. From 6.8, core uses bcrypt natively and these overrides should not be used.
