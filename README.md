# W55RP20 Web Board Control

A full **HTTPS server running on a single ~$2 chip** — the WIZnet **W55RP20**
(Raspberry Pi **RP2040** + **W5500** Ethernet controller in one package). It
serves a login-protected web UI that renders the board's real pinout: click any
pin to configure it as **GPIO, PWM, ADC, I2C, or SPI** and watch live values
update — straight from your browser, with **no cloud, no gateway, and no
companion app**.

> ⚠️ **Development project.** Functionality may be incomplete or unstable. The
> bundled TLS certificate is a self-signed demo cert — see
> [Certificate](#certificate).

---
<img width="483" height="274" alt="image" src="https://github.com/user-attachments/assets/6fec62bc-33aa-4583-b8c6-a043c5d2f5ab" />

<img width="1699" height="878" alt="image" src="https://github.com/user-attachments/assets/3b72e12b-286f-4fad-b48d-ec3bb6638e38" />

## Features

- **On-device HTTPS server** — TLS 1.2 via mbedTLS, port `443`, served entirely
  from flash (the web UI is embedded into the firmware at build time).
- **Login authentication** — passwords stored as SHA-256 hashes in flash,
  session cookies (`HttpOnly` + `Secure` + `SameSite`), 30-minute timeout, up to
  5 accounts.
- **Interactive pinout UI** — an SVG drawing of the W55RP20-EVB-Pico. Click a
  pin to open its configuration panel.
- **Per-pin peripherals**
  - Digital **Input** (with pull-up / pull-down) and **Output** (HIGH / LOW)
  - **PWM** (frequency + duty)
  - **ADC** (raw value + voltage + bar), GP26–28
  - **I2C** bus scan / register read / write
  - **SPI** hex transfer
- **Live values** — inputs and ADC refresh automatically; the pin map doubles as
  a real-time status display.

Controllable pins: **GP0–GP15** and **GP26–GP28**.

---

## How it works

```
Browser ──HTTPS(443)──▶ mbedTLS handshake
                            └─ session-cookie auth
                                 ├─ GET  /            → board UI (embedded HTML)
                                 ├─ GET  /api/pins    → JSON pin state (polled)
                                 ├─ POST /api/pin     → set pin mode / value
                                 └─ POST /api/i2c|spi → bus transactions
```

The web page lives as a normal `board.html`, then a CMake step converts it to a
C byte array (`board_page.h`) that is compiled into the firmware — there is no
filesystem. The firmware runs on FreeRTOS; one task drives the HTTPS server
across three W5500 sockets (up to three concurrent connections).

### Pages

| Route | Purpose |
|---|---|
| `/` | Board control (requires login) |
| `/login` | Login |
| `/setup` | First-run account creation |
| `/account` | Settings — add / delete accounts |
| `/logout` | Invalidate session |

### Account creation password

Creating accounts requires a separate creation password (demo default:
`w55rp20`). To change it, edit a single string —
`HTTPS_CREATION_PASSWORD` in
[`httpsAuth.h`](port/app/platform_handler/inc/httpsAuth.h) — and rebuild. It is
hashed with SHA-256 at runtime, so there is no precomputed hash to update.
**Change this for any real use.**

---

## Making TLS fast on an MCU

A naive HTTPS server on the RP2040 is slow. Three changes make it practical:

1. **Static-RSA ciphersuites only** — by default browsers pick ECDHE-RSA, but EC
   math is software-only on the RP2040 (multi-second handshakes). The server
   restricts to `TLS_RSA_WITH_AES_128_GCM_SHA256` and friends.
2. **HTTP keep-alive** — the first handshake still costs ~2.2 s (the floor for
   RSA-2048 at 200 MHz), but the connection is then reused for every page load,
   pin toggle, and status poll — no re-handshake.
3. **Tuned TLS record buffers** — IN 2 KB / OUT 8 KB to save RAM across three
   sockets while keeping responses to a few records.

> **Next:** an ECDSA P-256 certificate to bring the *first* handshake down from
> ~2.2 s to a few hundred ms.

---

## Key source files

| File | Role |
|---|---|
| [`port/app/platform_handler/src/httpHandler.c`](port/app/platform_handler/src/httpHandler.c) | HTTPS server task, routing, JSON API |
| [`port/app/platform_handler/src/httpsAuth.c`](port/app/platform_handler/src/httpsAuth.c) | Account / session management |
| [`port/app/platform_handler/src/pinCtrl.c`](port/app/platform_handler/src/pinCtrl.c) | GPIO / PWM / ADC / I2C / SPI control + JSON state |
| [`port/app/platform_handler/web/board.html`](port/app/platform_handler/web/board.html) | Interactive pinout web UI (embedded at build) |
| [`port/app/mbedtls/src/SSLInterface.c`](port/app/mbedtls/src/SSLInterface.c) | TLS context, ciphersuites, session cache |

---

## Socket allocation (W5500)

| Socket | Purpose |
|---|---|
| 0 | S2E data |
| 1 | Config UDP |
| 2 | Config TCP |
| 3 | DHCP / DNS |
| 4–6 | HTTPS server (3 concurrent) |
| 7 | Utility |

---

## Certificate

The HTTPS server ships with a **self-signed development certificate** embedded in
[`SSLInterface.c`](port/app/mbedtls/src/SSLInterface.c). Browsers will show a
security warning on first access — this is expected.

Private keys are **never committed**. To generate your own cert/key and embed it,
see [`cert_work/README.md`](cert_work/README.md).

---

## Build

This is a Raspberry Pi Pico SDK project (CMake). Initialize submodules, point
`PICO_SDK_PATH` at the bundled SDK, configure, and build:

```bash
git clone --recurse-submodules https://github.com/seok930927/W55RP20-Web-Board-Control.git
cd W55RP20-Web-Board-Control
cmake -B build
cmake --build build
```

Flash the resulting UF2/ELF to the W55RP20-EVB-Pico, connect Ethernet, and open
`https://<device-ip>/` in a browser.

---

## Hardware

- **W55RP20-EVB-Pico** (RP2040 + W5500 in a single SiP)
- Ethernet connection
- Any I2C / SPI peripheral you want to drive
