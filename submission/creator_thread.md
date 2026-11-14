# Creator Track: X thread for @Aryasakti80

**Creator form title:** Verification is necessary, not sufficient: building an AI payment agent that proves its own decisions (zkVerify Agent Games)

**Format:** Thread
**Link to submit:** URL of post 1 after posting

---

**1/7**
An AI agent gets a valid ZK proof and a payment request. Should it pay?

Not necessarily. A proof can verify perfectly and still back the wrong payment.

I built an agent that checks what was proven, then proves its own decision. 🧵

#AgentGames @ZKVProtocol

**2/7**
6 ways a valid proof backs a bad payment:
• made with a different verification key
• proven balance < minimum
• wrong recipient
• condition expired
• amount > transfer cap
• same proof replayed

Each is rejected by deterministic code, never an LLM.

**3/7**
The twist: the agent doesn't just say "REJECT". It returns a Groth16 proof (snarkjs, ~0.2s) that its decision is the output of the published rule.

The platform re-checks it against its own key registered on @ZKVProtocol mainnet. No trust in my server needed.

**4/7**
Why it can't cheat: the circuit only produces a witness for APPROVE if VKs match, balance ≥ min, recipients match, block < expiry and amount ≤ cap.

Replay is a cross-task property, so it's caught off-circuit by a persistent seen-set.

**5/7**
Same endpoint plays Steal the VFY, a 20-turn duel.

Before the match the agent commits Poseidon(strategy params + salt). On every move it proves the move came from that committed strategy, bound to matchId + turn. Opponents learn it followed the rules, not what the rules are.

**6/7**
Plumbing that matters:
• HMAC-SHA256 checked on the raw body before parsing
• every response signed
• fail closed: error → REJECT / HOLD
• idempotent per task and turn
• secrets only in env

45 tests pass. Committed example proofs re-verify with one command.

**7/7**
Agents will move money. "Trust me" isn't enough; "here's a proof" is.

Code, architecture diagram and verifiable examples:
https://github.com/aryasakti801/proof-gatekeeper-agent

#AgentGames @ZKVProtocol
