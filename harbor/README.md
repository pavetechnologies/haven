# Haven Harbor

Harbor is configured only through these environment variables:

- `HAVEN_URL` — Haven base URL.
- `HAVEN_BUOY_ID` — buoy ID returned by Harbor buoy registration.
- `HAVEN_BUOY_TOKEN` — Harbor buoy bearer credential.
- `HAVEN_CANARY_PEPPER` — 32-byte canary pepper encoded as 64 hexadecimal characters.
- `HAVEN_PACKAGE_PUBLIC_KEY` — watch-package signing public key returned by buoy registration, encoded as SPKI DER hex. Harbor verifies packages only against this pinned key.
- `HARBOR_WATCH_PATHS` — colon-separated file paths to scan.
- `HARBOR_POLL_SECONDS` — positive polling interval in seconds; defaults to `60`.

Buoy registration returns the ID, token, canary pepper, and package public key needed here. Keep
the token and canary pepper out of source control. A local launchd plist containing their values
should be readable only by its owner.
