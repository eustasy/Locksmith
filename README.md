Locksmith
=========

Cross-platform software license validation backend. Supports online activation
via a REST API and fully offline validation via signed license files. No frontend
is provided — integrate against the API or ship the public key with your application.

## License Fields

A license is composed of five independent dimensions. Each is validated separately;
they can be combined freely to express any commercial licensing model.

### Time

Controls how long the license is valid.

| Value | Description |
|:--|:--|
| `perpetual` | No expiry date. Valid indefinitely from `valid_from`. |
| `limited` | Expires on `expires_at`. The duration is arbitrary — 1 month, 1 year, 3 years, etc. |

### Version

Controls which application versions the license covers.

| Value | Description |
|:--|:--|
| `any` | Any version of the application is permitted. |
| `maintenance` | Only versions sharing the same major version as `major_version` are permitted. New major versions require a new or upgraded license. |
| `specific` | Only the exact version string in `locked_version` is permitted. |

### Edition

Controls which product editions are covered. `editions` is a list of
case-insensitive strings. Leave empty to allow any edition. Common values:

`home` · `pro` · `enterprise` · `server`

Custom editions (e.g. `"studio"`, `"ultimate"`) are supported — the vendor
defines the edition names; the client reports its edition at activation.

### Host OS

Controls which operating systems the license is valid on. `platforms` is a list
of case-insensitive strings. Leave empty to allow any platform.

Values can be broad or specific:

| Example value | Meaning |
|:--|:--|
| `windows` | Any Windows version. |
| `windows_server_2022` | Windows Server 2022 only. |
| `macos` | Any macOS version. |
| `linux` | Any Linux distribution. |

The client reports its platform string at activation. Naming is freeform — the
vendor decides the convention; it is embedded and signed into the license.

### Restriction

Controls how many simultaneous uses are permitted and how they are counted.

| Mode | Field | Description |
|:--|:--|:--|
| `activations` | `activation_limit` | Maximum number of distinct machines that may activate this license. Each machine is identified by its hardware-derived SHA-256 fingerprint. |
| `users` | `user_limit` | Maximum number of distinct named users (`DOMAIN\username`) that may be bound to this license. |
| `floating` | `concurrent_limit` | Maximum number of users or machines that may hold an active session concurrently. Check-out / check-in model. |

Omit all limit fields (or set to `null`) to place no restriction on activations.

---

## Entitlements

Entitlements allow a single license to govern **multiple applications** (bundles)
with independent constraints per application. Each entitlement is matched by
`app_id` and can specify its own edition, version, platform, and seat-count rules,
overriding the license-level defaults for that application.

| Field | Description |
|:--|:--|
| `app_id` | Reverse-domain identifier for the application (e.g. `com.example.myapp`). |
| `editions` | Allowed edition names for this app. Overrides the license-level `editions`. |
| `min_version` | Inclusive minimum app version (e.g. `"2.0.0"`). |
| `max_version` | Inclusive maximum app version (e.g. `"2.9.9"`). |
| `platforms` | Allowed host OS values for this app. Overrides the license-level `platforms`. |
| `seats` | Seat count override for this app. Falls back to the license-level limit if omitted. |

A license with **no entitlements** applies to all applications unconditionally.

**Bundle entitlements file** (`bundle.json`) example:
```json
[
  {
    "app_id": "com.example.editor",
    "editions": ["pro", "enterprise"],
    "min_version": "3.0.0",
    "seats": 5
  },
  {
    "app_id": "com.example.renderer",
    "platforms": ["windows", "linux"],
    "seats": 2
  }
]
```

---

## Quick Start

### 1. Install

```bash
pip install -e ".[dev]"
```

### 2. Generate a keypair (server, once only)

```bash
locksmith-setup --out-dir keys
```

Keep `keys/privkey.pem` secret. Distribute `keys/pubkey.pem` with your application.

### 3. Configure

```bash
cp .env.example .env
# Set LOCKSMITH_ADMIN_API_KEY to a strong random value:
python -c "import secrets; print(secrets.token_hex(32))"
```

### 4. Start the server

```bash
locksmith-serve
# Listening on http://0.0.0.0:8000
# Interactive docs at http://localhost:8000/docs
```

### 5. Issue a license

```bash
# Perpetual, any version, any edition, any platform — no restriction
locksmith-issue --email user@example.com

# 1-year license, Pro or Enterprise editions, Windows and Linux, max 3 activations
locksmith-issue --email user@example.com \
  --expires-days 365 \
  --editions pro,enterprise \
  --platforms windows,linux \
  --activation-limit 3

# Maintenance — covers major version 2.x only, any platform, 5 activations
locksmith-issue --email user@example.com \
  --version-policy maintenance --major-version 2 \
  --activation-limit 5

# Floating — max 10 concurrent sessions
locksmith-issue --email user@example.com \
  --restriction floating --concurrent-limit 10

# Bundle — multiple applications from a JSON file
locksmith-issue --email user@example.com \
  --entitlements-file bundle.json
```

---

## CLI Reference

| Command | Description |
|:--|:--|
| `locksmith-setup` | Generate an RSA keypair for the license server. |
| `locksmith-issue` | Sign and issue a `.lic` license file. Accepts a customer `.lsreq` file to skip manual entry. |
| `locksmith-verify` | Verify a `.lic` file offline using only the public key (development / support tool). |
| `locksmith-request` | Run on the customer's machine to generate a `.lsreq` request file to send to the vendor. |
| `locksmith-serve` | Start the FastAPI license server. |

## API Endpoints

| Method | Path | Auth | Description |
|:--|:--|:--|:--|
| `GET` | `/health` | None | Liveness probe. |
| `POST` | `/licenses` | Admin | Issue a new license; returns the raw `.lic` JSON. |
| `GET` | `/licenses/{id}` | Admin | Retrieve license metadata, entitlements, and usage counts. |
| `DELETE` | `/licenses/{id}` | Admin | Revoke a license immediately. |
| `POST` | `/activate` | None | Online activation — verifies the license and records the machine or user against the appropriate limit. |
| `POST` | `/validate` | None | Offline validation — accepts a `.lic` file upload and returns a verification result. |
| `POST` | `/request` | None | Accept a customer `.lsreq` file and queue it for vendor review. |

**`POST /activate` fields:** `license_id`, `machine_id`, `app_id`, `app_version`, `edition` (optional), `platform` (optional).

**`POST /validate` form fields:** `file` (`.lic`), `app_version`, `app_id`, `edition`, `platform` — all optional except `file`.

Admin routes require `Authorization: Bearer <LOCKSMITH_ADMIN_API_KEY>`.

---

## Offline Flow

1. Customer runs `locksmith-request` on their machine → produces `customer.lsreq`
2. Customer sends `customer.lsreq` to the vendor
3. Vendor runs `locksmith-issue --request-file customer.lsreq` → produces `license.lic`
4. Vendor sends `license.lic` back to the customer
5. Customer places `license.lic` in the application directory
6. Application calls `validate_license(License.from_file("license.lic"), signer, ...)` — fully offline

> **Note:** Revocation and floating seat check-in/check-out require a network connection. Offline licenses rely on expiry as the revocation backstop.

---

## Extending to KMS

`FileSigner` (local PEM files) implements the `BaseSigner` abstract interface in
`locksmith/core/keys.py`. To use AWS KMS, HashiCorp Vault, or any other signing
backend, implement `BaseSigner.sign()` and `BaseSigner.verify()` and pass your
implementation to `create_app()` via `app.state.signer`.

## Running Tests

```bash
pytest --cov=locksmith
```

Entitlements allow a single license to govern **multiple applications** (bundles) with independent constraints per app. Each entitlement is matched by `app_id` and can restrict:

| Field | Description |
|:--|:--|
| `app_id` | Reverse-domain identifier for the application (e.g. `com.example.myapp`). |
| `editions` | Allowed edition names, case-insensitive (e.g. `["professional", "enterprise"]`). Omit for any edition. |
| `min_version` | Inclusive minimum app version string (e.g. `"2.0.0"`). Omit for no minimum. |
| `max_version` | Inclusive maximum app version string (e.g. `"2.9.9"`). Omit for no maximum. |
| `platforms` | Allowed host OS values: `"windows"`, `"macos"`, `"linux"`. Omit for any platform. |
| `seats` | Per-app seat count override. Falls back to the license-level `seats` if omitted. |

A license with **no entitlements** applies to all applications unconditionally.

**Bundle entitlements file** (`bundle.json`) example:
```json
[
  {
    "app_id": "com.example.editor",
    "editions": ["professional", "enterprise"],
    "min_version": "3.0.0",
    "seats": 5
  },
  {
    "app_id": "com.example.renderer",
    "platforms": ["windows", "linux"],
    "seats": 2
  }
]
```

## Quick Start

### 1. Install

```bash
pip install -e ".[dev]"
```

### 2. Generate a keypair (server, once only)

```bash
locksmith-setup --out-dir keys
```

Keep `keys/privkey.pem` secret. Distribute `keys/pubkey.pem` with your application.

### 3. Configure

```bash
cp .env.example .env
# Set LOCKSMITH_ADMIN_API_KEY to a strong random value:
python -c "import secrets; print(secrets.token_hex(32))"
```

### 4. Start the server

```bash
locksmith-serve
# Listening on http://0.0.0.0:8000
# Interactive docs at http://localhost:8000/docs
```

### 5. Issue a license

```bash
# Simple perpetual — no application restriction
locksmith-issue --type perpetual --email user@example.com --seats 2

# Single app — Professional edition only, versions 2.x, Windows and Linux only
locksmith-issue --type perpetual --email user@example.com \
  --app-id com.example.myapp \
  --editions professional \
  --min-version 2.0.0 --max-version 2.9.9 \
  --platforms windows,linux

# Bundle — multiple applications from a JSON file
locksmith-issue --type perpetual --email user@example.com \
  --entitlements-file bundle.json
```

## CLI Reference

| Command | Description |
|:--|:--|
| `locksmith-setup` | Generate an RSA keypair for the license server. |
| `locksmith-issue` | Sign and issue a `.lic` license file. Accepts a customer `.lsreq` file to skip manual entry. |
| `locksmith-verify` | Verify a `.lic` file offline using only the public key (development / support tool). |
| `locksmith-request` | Run on the customer's machine to generate a `.lsreq` request file to send to the vendor. |
| `locksmith-serve` | Start the FastAPI license server. |

## API Endpoints

| Method | Path | Auth | Description |
|:--|:--|:--|:--|
| `GET` | `/health` | None | Liveness probe. |
| `POST` | `/licenses` | Admin | Issue a new license; returns the raw `.lic` JSON. Accepts `entitlements` array. |
| `GET` | `/licenses/{id}` | Admin | Retrieve license metadata, entitlements, and active seat count. |
| `DELETE` | `/licenses/{id}` | Admin | Revoke a license immediately. |
| `POST` | `/activate` | None | Online activation — verifies the license, matches the entitlement, checks per-app seat count, records the machine. |
| `POST` | `/validate` | None | Offline validation — accepts a `.lic` file upload and returns a verification result. |
| `POST` | `/request` | None | Accept a customer `.lsreq` file and queue it for vendor review. |

**`POST /activate` fields:** `license_id`, `machine_id`, `app_id`, `app_version`, `edition` (optional), `platform` (optional).

**`POST /validate` form fields:** `file` (`.lic`), `app_version`, `app_id`, `edition`, `platform` — all optional except `file`.

Admin routes require `Authorization: Bearer <LOCKSMITH_ADMIN_API_KEY>`.

## Seat Counting

Seats are tracked **per application**. Each app's seat count uses the entitlement's `seats` field, falling back to the license-level `seats`. A single bundle license can therefore allow 5 seats for the editor and 2 for the renderer independently.

1. Customer runs `locksmith-request` on their machine → produces `customer.lsreq`
2. Customer sends `customer.lsreq` to the vendor
3. Vendor runs `locksmith-issue --request-file customer.lsreq` → produces `license.lic`
4. Vendor sends `license.lic` back to the customer
5. Customer places `license.lic` in the application directory
6. Application calls `validate_license(License.from_file("license.lic"), signer, ...)` — fully offline

## Extending to KMS

`FileSigner` (local PEM files) implements the `BaseSigner` abstract interface in
`locksmith/core/keys.py`. To use AWS KMS, HashiCorp Vault, or any other signing
backend, implement `BaseSigner.sign()` and `BaseSigner.verify()` and pass your
implementation to `create_app()` via `app.state.signer`.

## Running Tests

```bash
pytest --cov=locksmith
```
