# zkVerify Agent Games — Proof Gatekeeper

Local HTTPS-ready agent for the [Proof Gatekeeper](https://agentgames.zkverify.io/events/proof-gatekeeper) track.

The platform POSTs a signed task to `POST /agent`. This service checks the payment fields, returns `APPROVE` or `REJECT` with a canonical reason code, and (except for `PROOF_REUSED`) attaches a Groth16 proof from the official `gatekeeper.wasm` / `gatekeeper_final.zkey` artifacts. Proof generation takes ~300ms on this box.

## Run locally

```bash
cp .env.example .env
# set AGENT_GAMES_HMAC_SECRET
npm start          # POST http://127.0.0.1:8787/agent
npm test
```

## What still needs the user

1. Sign in at https://agentgames.zkverify.io/register with X or an EVM wallet (WalletConnect). Entry is free. Do not pay anything.
2. Handle, country, short bio. Connect GitHub + a payout wallet before the event closes if you want prize eligibility.
3. After a public HTTPS URL exists (no localhost, no custom ports), register the full path `https://<host>/agent`.
4. Dashboard → Rotate Secret, put the one-time value in `.env` as `AGENT_GAMES_HMAC_SECRET` (never commit it, never paste it in chat).
5. Run preflight, then at least one practice task, then enter Proof Gatekeeper. Entries lock while a scored round is open.

## Hosting

Keep this process running 24/7 during 13–21 Nov 2026, 17:30–03:30 WIB (16:00–02:00 IST) daily rounds. A Cloudflare named tunnel or any always-on HTTPS reverse proxy works. A `cloudflared` quick tunnel is fine for practice but the URL changes on restart, so it is a poor fit for the whole event unless the process never dies and you re-register after every restart.

## Circuit notes

13 inputs: 12 public + private `salt`. Public signals: commitment, both VK hashes, threshold fields, addresses, amount cap, decision (1=approve, 0=reject), taskId. Approve is valid only when VKs match, `publicBalance >= minimum`, recipients match, `currentBlock < expiryBlock`, and `amount <= maxTransfer`.
