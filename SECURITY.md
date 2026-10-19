# Security

## Reporting a problem

Please report it privately through GitHub: the repository's **Security** tab, then **Report a vulnerability**. Don't
open a public issue. You'll get an answer within a week, and a fixed release as soon as the fix is verified.

## Supported versions

Fixes go into the latest release only.

## What this library does to keep hashes safe

- **Constant-time check.** The computed hash is compared with the stored one using
  `CryptographicOperations.FixedTimeEquals`; a test times it against an early-exit comparison.
- **No silent truncation.** bcrypt reads at most 72 bytes of a password. A longer password is refused (`Hash`
  throws, `Verify` returns false) instead of being cut, so two passwords that share their first 72 bytes never match
  each other. `EnhancedHash` digests the password with SHA-2 first and takes any length.
- **No lossy text.** A password that isn't valid UTF-16 (a lone surrogate) is refused rather than turned into U+FFFD,
  which would make different passwords hash alike.
- **Strict parsing.** Only `$2a$`, `$2b$`, `$2y$` and `$2$` hashes with a cost of 4 to 31 are accepted. `$2x$`
  (PHP's buggy hashes from before 5.3.7) is refused. A malformed hash never matches and never throws.
- **Wiped buffers.** Key material, the expanded Blowfish state and the queue's pooled requests are zeroed after use.
- **Random salts** come from `RandomNumberGenerator`.

## Things to do in your application

- Check a hash even when the account doesn't exist (against a fixed dummy hash), so response times don't reveal
  which accounts exist.
- Use a cost of at least 10; raise it over time and use `PasswordNeedsRehash` to upgrade hashes at sign-in.
- Limit sign-in attempts. With `BcryptQueue`, set `MaxQueued` so a flood of sign-ins is refused quickly instead of
  queueing minutes of work.
