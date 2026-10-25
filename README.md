<p align="center"><img src="DiscordProxy.png" width="128" alt="Discord Proxy logo"></p>

<p align="center">
  <a href="https://github.com/smhamirii/Discord-Proxy/releases/latest">
    <img src="https://img.shields.io/badge/Download-Discord%20Proxy.exe-5865F2?style=for-the-badge&logo=windows" alt="Download">
  </a>
</p>

# Discord Proxy

**Route only Discord through your proxy. Everything else stays on your normal connection.**

Discord Proxy is a small Windows GUI that sends **only Discord's traffic** (text, uploads *and* UDP voice) through a proxy you provide. Your games, Steam, browser and Windows itself are never touched.

```
Discord.exe / DiscordPTB.exe / DiscordCanary.exe  ──►  your proxy
everything else                                   ──►  DIRECT (your ISP)
```

> 🟢 **Open source.** The whole program is a single readable Python file, and the routing logic lives in one function (`build_singbox_config`), so you can see exactly what it does with your traffic.
>
> 🤖 **Built with AI.** This program was written with **Claude Sonnet 5.5**.

---

## Download

Get **`Discord Proxy.exe`** from releases section and run it as Administrator.

Prefer to run from source? Install Python 3.10+ (with tcl/tk) and run:

```
python discord_proxy.py
```

---

## Features

### Per-app routing (not a system-wide VPN)
- Only `Discord.exe`, `DiscordPTB.exe` and `DiscordCanary.exe` are sent through the proxy.
- No system proxy setting is changed, no `0.0.0.0/0` route is added, and your default gateway is untouched.
- Anything that matches no rule falls through to **direct**.
- Private/LAN addresses (router, local PCs, etc.) are never proxied.
- Works for **TCP and UDP**, so Discord **voice calls** go through the proxy too.

### Smart DNS handling
- Discord's domains get a placeholder ("fake") IP and the proxy server does the real lookup, so poisoned local DNS answers are never used.
- All other DNS keeps resolving through Windows normally.
- Other programs that do their own DNS (games, TeamSpeak, torrent clients, VPN tools) are left alone.
- Discord's HTTP/3 (QUIC) attempts are rejected so it falls back to TCP right away, which fixes file uploads that fill the progress bar and then fail.
- Covers Discord's domains plus the exact Google Cloud Storage hostname used for attachment uploads.

### Supported proxy links
Paste a link, or a sing-box / Xray outbound JSON object:

- `vless://`
- `vmess://`
- `trojan://`
- `ss://` (Shadowsocks)
- `hysteria2://` / `hy2://`
- `tuic://`
- `wireguard://` / `wg://`

Transports include TCP, WebSocket, gRPC, HTTP, HTTPUpgrade and **XHTTP**. TLS and Reality settings are parsed from the link.

### Two proxy cores
- **sing-box** handles the TUN adapter and per-process routing.
- **Xray-core** (optional) is used automatically for XHTTP, mKCP and raw Xray JSON configs, which sing-box can't do. sing-box stays in front and just chains to a local Xray instance.
- Choose **Auto**, **sing-box** or **Xray-core** in the main window.

### Server list
- Save as many proxy links as you want, with rename, remove and reorder.
- Add the current link or paste several links at once.
- **Test all** measures latency for every saved server, and **Sort** orders them by speed.
- One-click switch to the selected server.
- **Auto-switch (failover):** if the active server stops answering, the app moves to the next healthy saved link and skips ones that just failed.

### Connection monitoring
- **Health checks** measure the proxy against Discord's real gateway. A slow or lost sample doesn't count as a failure; a majority has to fail.
- **Auto-recovery** restarts the chain if it really dies (with limits, so it can't loop forever). It deliberately avoids restarting on a merely weak link, because that would drop your voice call.
- **Voice stall watchdog:** if a voice flow keeps sending but receives nothing, only that flow is reset so the call recovers without leaving and rejoining.
- **Voice check:** after Discord joins a voice server, the app verifies the UDP media is actually going through the tunnel.
- **Traffic counter:** total upload and download.
- **Voice status:** idle / ok / stalled / recovering, with live up/down rate and reset count.
- **Voice quality readout (optional):** ping, packet loss and jitter with a quality grade, measured by a few tiny UDP packets per second sent through the same proxy path as Discord.
- **Voice ping graph** for the last hour, with connection events.

### Network capture modes (Settings → Network)
- **Only Discord's destinations (default):** the TUN adapter only gets routes for Discord's destinations, so other programs' packets never enter it. Voice server ranges are learned automatically from Discord's own connections.
- **Everything:** the TUN takes the default route and sing-box decides per process. Most reliable.
- Falls back safely if ranges or system DNS can't be determined.
- Editable ranges file: add CIDRs, or prefix with `-` to exclude a range so a game's servers can never enter the tunnel.
- Advanced TUN options: **strict route** on/off, **TUN stack** (mixed / system / gvisor) and **MTU**.

### Convenience
- **Smart auto-start:** start and stop the proxy together with Discord.
- **Start with Windows:** creates a Task Scheduler entry that launches in the tray at sign-in, with an optional delay.
- **System tray icon** with state colours, notifications and quick Start/Stop.
- **Close behaviour:** ask every time, minimize to tray (default), or exit completely.
- **Open Discord / Close Discord** buttons, and detection of Stable, PTB and Canary.
- **Test Proxy** button, **Retry** button and plain-language explanations of common failures.
- **Live log panel** with search, "Errors only", "Discord only", copy and clear.
- **Export Log (.txt)** and **Open Config Folder**.
- **Light / dark / system theme**, remembered window position and a single-instance guard.
- **Restart as Administrator** button (the TUN adapter needs elevation).

### Components and updates
- Shows whether `sing-box.exe`, `wintun.dll`, `xray.exe`, Administrator rights and Discord are present.
- Offers to **download missing components from their official sources, only after you confirm**.
- Downloads are checked against the **SHA-256** published by GitHub, and wintun is checked with an **Authenticode** signature check.
- Detects your CPU architecture (amd64 / arm64 / 386) so you get the right build.
- Optional warning when sing-box or Xray-core is outdated, plus a one-click **Update**. This only reads the newest version number from GitHub.

### Privacy and security
- **Secrets are masked in the log:** UUIDs, passwords, keys and whole proxy links are hidden, including in exported logs.
- **Your saved link is encrypted** with Windows DPAPI, tied to your Windows user account.
- **Generated configs are deleted** when the proxy stops and when the app exits, since they contain credentials.
- The local stats API listens only on `127.0.0.1` with a random port and random secret.
- Leftover adapters and processes from a crash are cleaned up on startup.
- **Reset all settings** wipes saved data.
- **No telemetry.** The only network activity is your proxy, plus the update check and component downloads described above.

---

## Requirements

1. Windows 10 or 11
2. Administrator rights (needed to create the TUN adapter)
3. `sing-box.exe` and `wintun.dll` in the same folder as the app (the app can download them for you)
4. `xray.exe`, **only** if your link uses XHTTP / mKCP / raw Xray JSON
5. **A proxy of your own.** A `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`, `tuic://` or `wireguard://` link from a server you trust. **This project does not include or recommend any proxy.**

## How to use

1. Run `Discord Proxy.exe` as Administrator.
2. Click **Get missing files...** if anything shows red.
3. Paste your proxy link.
4. Click **Test Proxy** (optional).
5. Click **Start Discord Proxy**, then open Discord.
6. Join a voice channel once so the app can learn Discord's voice ranges.

---

## Credits

Built on top of these open-source projects, which are **not bundled** and are only downloaded if you confirm:

- [sing-box](https://github.com/SagerNet/sing-box) (proxy engine and TUN routing)
- [Xray-core](https://github.com/XTLS/Xray-core) (XHTTP support)
- [Wintun](https://www.wintun.net/) (TUN adapter driver)

## Disclaimer

This tool is provided as is, with no warranty. You are responsible for the proxy you use and for following the laws and terms of service that apply to you. It is not affiliated with or endorsed by Discord.

## License

Open source. See the [`LICENSE`](LICENSE) file for details.

## Contributing

Issues and pull requests are welcome.
