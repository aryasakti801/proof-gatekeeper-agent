import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { groth16 } from 'snarkjs';
import { hexToField, utf8ToField, intToField, fieldToString } from './fields.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const WASM_PATH = path.join(root, 'circuits', 'gatekeeper.wasm');
export const ZKEY_PATH = path.join(root, 'circuits', 'gatekeeper_final.zkey');
export const VKEY_PATH = path.join(root, 'circuits', 'verification_key.json');

/**
 * Public signals order produced by this circuit (nPublic=13):
 *  [0]  salted commitment (depends on private `salt`)
 *  [1]  registeredVkHash
 *  [2]  proofVkHash
 *  [3]  minimum
 *  [4]  publicBalance
 *  [5]  expiryBlock
 *  [6]  currentBlock
 *  [7]  recipient
 *  [8]  conditionRecipient
 *  [9]  amount
 *  [10] maxTransfer
 *  [11] decision          // 1 = APPROVE, 0 = REJECT
 *  [12] taskId
 */
export function buildCircuitInput(task, { circuitDecision, salt = 0n }) {
  const input = task.input ?? task;
  const taskId = task.task_id ?? task.taskId ?? input.task_id;
  return {
    registeredVkHash: fieldToString(hexToField(input.registered_vk)),
    proofVkHash: fieldToString(hexToField(input.proof_vk)),
    minimum: fieldToString(intToField(input.minimum)),
    publicBalance: fieldToString(intToField(input.public_balance)),
    expiryBlock: fieldToString(intToField(input.expiry_block)),
    currentBlock: fieldToString(intToField(input.current_block)),
    recipient: fieldToString(hexToField(input.recipient)),
    conditionRecipient: fieldToString(hexToField(input.condition_recipient)),
    amount: fieldToString(intToField(input.amount)),
    maxTransfer: fieldToString(intToField(input.max_transfer)),
    taskId: fieldToString(utf8ToField(taskId)),
    decision: fieldToString(circuitDecision),
    salt: fieldToString(typeof salt === 'bigint' ? salt : intToField(salt)),
  };
}

export async function proveDecision(task, { circuitDecision, salt = 0n }) {
  const circuitInput = buildCircuitInput(task, { circuitDecision, salt });
  const { proof, publicSignals } = await groth16.fullProve(
    circuitInput,
    WASM_PATH,
    ZKEY_PATH,
  );
  return {
    proof: {
      pi_a: proof.pi_a,
      pi_b: proof.pi_b,
      pi_c: proof.pi_c,
      protocol: proof.protocol,
      curve: proof.curve,
    },
    public_signals: publicSignals,
  };
}

export async function verifyProof(proof, publicSignals, vkey) {
  return groth16.verify(vkey, publicSignals, proof);
}
