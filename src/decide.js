/**
 * Deterministic Proof Gatekeeper policy.
 *
 * On-circuit rules (from gatekeeper.wasm, template GatekeeperEvaluation_79):
 *   APPROVE (decision=1) iff ALL of:
 *     registeredVkHash == proofVkHash
 *     publicBalance >= minimum
 *     recipient == conditionRecipient
 *     currentBlock <  expiryBlock     // equality is expired
 *     amount <= maxTransfer
 *   Otherwise only decision=0 produces a valid witness.
 *
 * Off-circuit: proof reuse is detected from the local seen-set of previously
 * APPROVED proof_tx values. The official scoring text says PROOF_REUSED
 * tasks have no Groth16 proof to submit — the circuit would require
 * decision=1 when the field checks pass.
 *
 * Reason-code priority when several traps fire (first match wins):
 *   VK_SUBSTITUTION, THRESHOLD_MISMATCH, RECIPIENT_MISMATCH,
 *   EXPIRED_CONDITION, AMOUNT_OVERFLOW, then PROOF_REUSED.
 * Canonical rules-page aliases (PROOF_REPLAY, etc.) are documented in README.
 */

export const REASON = {
  VALID_PROOF: 'VALID_PROOF',
  VK_SUBSTITUTION: 'VK_SUBSTITUTION',
  THRESHOLD_MISMATCH: 'THRESHOLD_MISMATCH',
  RECIPIENT_MISMATCH: 'RECIPIENT_MISMATCH',
  EXPIRED_CONDITION: 'EXPIRED_CONDITION',
  AMOUNT_OVERFLOW: 'AMOUNT_OVERFLOW',
  PROOF_REUSED: 'PROOF_REUSED',
  PROOF_INVALID: 'PROOF_INVALID',
  MISSING_VERIFICATION: 'MISSING_VERIFICATION',
};

export function normalizeHex(value) {
  if (value == null) return '';
  let s = String(value).trim().toLowerCase();
  if (s.startsWith('0x')) s = s.slice(2);
  s = s.replace(/^0+/, '');
  return s;
}

export function decide(input, { seenProofTx = false } = {}) {
  const registered = normalizeHex(input.registered_vk);
  const proofVk = normalizeHex(input.proof_vk);
  const minimum = BigInt(String(input.minimum));
  const publicBalance = BigInt(String(input.public_balance));
  const expiryBlock = BigInt(String(input.expiry_block));
  const currentBlock = BigInt(String(input.current_block));
  const recipient = normalizeHex(input.recipient);
  const conditionRecipient = normalizeHex(input.condition_recipient);
  const amount = BigInt(String(input.amount));
  const maxTransfer = BigInt(String(input.max_transfer));

  if (registered !== proofVk) {
    return { decision: 'REJECT', reason_code: REASON.VK_SUBSTITUTION, circuitDecision: 0n, includeProof: true };
  }
  if (publicBalance < minimum) {
    return { decision: 'REJECT', reason_code: REASON.THRESHOLD_MISMATCH, circuitDecision: 0n, includeProof: true };
  }
  if (recipient !== conditionRecipient) {
    return { decision: 'REJECT', reason_code: REASON.RECIPIENT_MISMATCH, circuitDecision: 0n, includeProof: true };
  }
  if (currentBlock >= expiryBlock) {
    return { decision: 'REJECT', reason_code: REASON.EXPIRED_CONDITION, circuitDecision: 0n, includeProof: true };
  }
  if (amount > maxTransfer) {
    return { decision: 'REJECT', reason_code: REASON.AMOUNT_OVERFLOW, circuitDecision: 0n, includeProof: true };
  }
  if (seenProofTx) {
    return { decision: 'REJECT', reason_code: REASON.PROOF_REUSED, circuitDecision: 1n, includeProof: false };
  }
  return { decision: 'APPROVE', reason_code: REASON.VALID_PROOF, circuitDecision: 1n, includeProof: true };
}
