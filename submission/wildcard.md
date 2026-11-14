# Wildcard submission: form fields

**Project title**
Proof Gatekeeper Agent: a payment guard that proves its own decisions

**Agent link (repo)**
https://github.com/aryasakti801/proof-gatekeeper-agent

**Public endpoint**
https://daffodil-dismantle-helper.ngrok-free.dev/agent
(HMAC-signed POSTs only; unsigned requests get 401. Health check: https://daffodil-dismantle-helper.ngrok-free.dev/health)

**What it does**
AI agents that release payments usually trust whatever proof they are handed. But a valid proof can still back the wrong payment: a swapped verification key, a balance under the minimum, the wrong recipient, an expired condition, an amount over the cap, or a replayed proof. This agent checks every field of a proof-backed payment request with deterministic code, never an LLM, and fails closed. It then proves its own APPROVE/REJECT with a real Groth16 proof (snarkjs, official zkVerify-registered circuit), so anyone can check the decision followed the rule without trusting the agent's server. The same endpoint plays Steal the VFY: it commits to a hidden strategy (a Poseidon commitment) and proves every move matches it, revealing nothing about the strategy. Everything is HMAC-signed, idempotent, and covered by 45 automated tests.

**Use case / who it helps**
Teams running agent-driven payouts, escrow, grant or treasury releases who need every automated approval to be auditable: "the agent says it checked" becomes "here is a proof that the published rule produced this decision".

**Build context (how it works, key decisions)**
- Node.js + Express with a raw-body parser. The HMAC-SHA256 signature is checked before any parsing, and every response is signed.
- `src/decide.js` rules mirror the circuit exactly, so a correct decision always has a valid witness. APPROVE proofs are impossible for trapped requests.
- Proofs are generated locally from the official `gatekeeper.wasm/zkey` and `vfy-policy.wasm/zkey` in about 0.1–0.3 s. The platform re-verifies them against its own key registered on zkVerify mainnet.
- I recovered the circuit interfaces from the compiled wasm (input-name hashes and constraint logic) and pinned them with tests.
- Proof reuse is a cross-task property, so it is enforced off-circuit by a persistent seen-set.
- Steal the VFY: the strategy params and salt stay private in env. Each turn's proof is bound to (matchId, turn) and carries the keccak publicInputsHash the platform recomputes.

**zkVerify: the checkable claim**
"For task X with public fields F, this agent's decision D is the output of the published gatekeeper rule." Steal the VFY: "move M at turn T of match ID is the output of the strategy committed as C." Both are Groth16/BN254 proofs against verification keys registered on zkVerify mainnet (gatekeeper vk_hash 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0, vfy-policy vk_hash 0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047).

**Proof reference**
Locally verified Groth16 proofs committed in the repo. Anyone can re-check them with `node tools/verify-examples.mjs`:
- Gatekeeper (VK-substitution trap gives REJECT, decision signal 0): https://github.com/aryasakti801/proof-gatekeeper-agent/blob/main/examples/gatekeeper-response.json (task: https://github.com/aryasakti801/proof-gatekeeper-agent/blob/main/examples/gatekeeper-task.json)
- Steal the VFY policy proof (EXTRACT 5, publicInputsHash 0x8b99a63689fd1d6034e8a6c32945522c2dffb073b624898dd741df64161ee97d): https://github.com/aryasakti801/proof-gatekeeper-agent/blob/main/examples/vfy-response.json
(I haven't posted an on-chain zkVerify transaction from my side. The platform verifies the proofs it receives against its registered keys.)

**Additional links**
- Write-up and architecture diagram: https://github.com/aryasakti801/proof-gatekeeper-agent#readme
- Test suite (45 checks): https://github.com/aryasakti801/proof-gatekeeper-agent/blob/main/test/harness.js
- Agent Games profile: aryasakti80
- X: https://x.com/Aryasakti80

**Message to judges**
I built this around one idea from the Agent Games brief: verification is necessary, not sufficient. The agent never treats "the proof verifies" as "pay". It checks what was proven, then proves its own decision so nobody has to trust it. It is live in Proof Gatekeeper (preflight passed, practice trap answered correctly). The repo is small and readable, and every claim in the README can be reproduced with two commands: `npm test` and `node tools/verify-examples.mjs`. Thanks for reviewing!
