# Haven · license notes

Haven (identity, tokens, PEP, ledger, encrypted secret values, operator UI) is original work for this repository.

AES-256-GCM at rest uses the standard construction: 12-byte IV, ciphertext, 16-byte auth tag, stored as `iv || ciphertext || tag`.

Do not commit credential values, admin keys, or token secrets.

Third-party libraries keep their own licenses (Bun, React, Vite, etc.).
