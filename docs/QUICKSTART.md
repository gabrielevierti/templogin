# Start here

**You need:** Node.js 24 or later, npm, and a browser. A phone is optional. You do not need a streaming account, tempLogin account, passkey, API key or cloud database to evaluate the reference.

## 1. Launch

From the extracted or cloned `templogin` folder:

```sh
npm ci
npm run dev
```

Open **http://localhost:3000**. The Overview introduces the product; **Live demo** opens the simulated TV; **Developer guide** explains the complete walkthrough and integration points inside the app.

## 2. Test on one computer

1. On **Live demo**, choose **Connect with tempLogin**.
2. Under the QR, choose **Open the phone flow in another tab**.
3. Choose **Continue with demo account**. This represents an existing account at the fictional Screen Demo provider.
4. Match the code, choose **15 seconds · quick expiry test**, check the confirmation box and choose **Authorize this TV**.
5. Return to the TV tab. **You’re connected** appears with a running countdown; it closes automatically at expiry.

For a longer session, choose **1 hour**. From the phone tab, choose **Manage sessions → Revoke access**. The TV should close after its next resource check, normally within about three seconds while the page is active and the network is available. This is a demo polling interval, not a production SLA.

## 3. Test with an iPhone or Android phone

On macOS, install the optional tunnel once:

```sh
brew install cloudflared
```

Then, from the repository:

```sh
npm run dev:phone
```

Open the **public HTTPS `/tv` link printed in the terminal on your computer**, then scan its QR with your phone. Follow the same steps. No tempLogin passkey is involved. Keep the terminal running.

Do not reuse a QR from a localhost tab: localhost on the phone is the phone itself. The tunnel URL changes on restart. It is publicly reachable while running, uses a separate temporary database, and stops with Ctrl+C. Do not use real personal data in the fictional-provider demo. For other operating systems, install cloudflared using the official installation guide.

Official tunnel documentation: https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/

## What this proves

The QR handoff, consent, single-use exchange, session deadline, guarded-resource checks and revocation use the actual reference backend and SQL database. Only the provider login is simulated. No Netflix, Google, YouTube or Disney+ account is connected; the protected resource is not a commercial video.

## Next steps by role

| You are evaluating… | Read next |
|---|---|
| Product value and pilot scope | [Partner brief](PARTNER-BRIEF.md) |
| The experience and expected outcomes | [Evaluation walkthrough](EVALUATION.md) |
| Backend and identity integration | [Integration guide](INTEGRATION.md) |
| TV, player and media behavior | [Pilot checklist](PILOT-CHECKLIST.md) |
| Security controls and limitations | [Threat model](THREAT-MODEL.md) and [validation](VALIDATION.md) |
| Publishing the open-source project | [GitHub instructions](GITHUB.md) |

## Troubleshooting

| Symptom | Action |
|---|---|
| The phone opens localhost | Start `npm run dev:phone` and open its new HTTPS TV URL before scanning. |
| A passkey or security-key prompt appears | You are likely using an older build or different provider login. Restart this release and open its printed link. Screen Demo never requests WebAuthn. |
| cloudflared is missing | Install it first, or use the two-tab local walkthrough. |
| The code expired | Generate a new code on the TV. Pairing codes last five minutes. |
| The TV never connects | Check the code match, confirmation box and approval result; keep both pages open and check network reachability. |
| Session expired or revoked | Start a new request. Reusing the old code or credential is intentionally rejected. |
| Too many requests | Wait a minute before retrying; reference-host rate limits are active. |
| Production says setup is required | Supply a verified provider adapter. Demo identity is deliberately unavailable in production. |
| Node/build errors | Check `node --version` is 24+ and run `npm ci` from the folder containing package.json. |
