import fs from 'fs';
import WCB from '../node_modules/circom_runtime/js/witness_calculator.js';
import { fnvHash } from '../node_modules/circom_runtime/js/utils.js';
const wasm = fs.readFileSync(process.argv[2]);
const wc = await WCB(wasm);
const ex = wc.instance.exports;
console.log('inputSize', ex.getInputSize(), 'witnessSize', ex.getWitnessSize());
const base = process.argv.slice(3).join(',').split(',');
const words = ['strategy','commitment','strategyCommitment','commitmentHash','strategyHash','hash','matchId','match','turn','turnNumber','selfBalance','opponentBalance','balance','oppBalance','myBalance','action','actionType','amount','extractAmount','circuitVersion','version','publicInputsHash','inputsHash','pubHash','salt','strategySalt','params','strategyParams','param','p','w','weights','threshold','thresholds','selfFortifiedUntilTurn','opponentFortifiedUntilTurn','selfFortified','opponentFortified','fortified','oppFortified','nonce','resolverVersion','actionCode','actionAmount','publicInputsHashHi','publicInputsHashLo','publicInputsHashHigh','publicInputsHashLow','hashHi','hashLo','inputsHashHi','inputsHashLo','matchIdHi','matchIdLo','matchIdHash','commitHash','stateHash','gameState','state','selfFort','oppFort','lead','diff','margin','extractThreshold','fortifyThreshold','holdThreshold','maxExtract','extractMax','aggression','mode','policy','policyParams','strategyId','paramA','paramB','paramC','paramD','param0','param1','param2','param3','param4','param5','k','a','b','c','d','x','y','s','m','t','turnIndex','totalTurns','remainingTurns','turnsLeft','fortifyCost','extractCap','selfBal','oppBal','opponentFortifiedUntil','selfFortifiedUntil','selfFortifyUntil','oppFortifyUntil','publicHash','inputHash','phHi','phLo','pih','policyHash','policyCommitment','strategyCommit','actionId','actionKind','kind','decision','choice','move','moveType','moveAmount','amt','n','N','paramsHash','strategySeed','seed','secret','privateSalt','rand','randomness','fortifiedSelf','fortifiedOpponent','selfFortifiedTurn','opponentFortifiedTurn','selfIsFortified','opponentIsFortified','opponentFortifiedUntilTurnPlusOne','selfFortifiedUntilTurnPlusOne','hasSelfFortify','hasOpponentFortify','commitmentHi','commitmentLo','strategyCommitmentHash', ...base];
for (const w of [...new Set(words)]) {
  const h = fnvHash(w);
  const msb = parseInt(h.slice(0,8),16), lsb = parseInt(h.slice(8,16),16);
  let sz;
  try { sz = ex.getInputSignalSize(msb, lsb); } catch(e) { sz = 'ERR'; }
  if (sz !== -1 && sz !== 'ERR' && sz >= 0) console.log('FOUND', w, sz);
}
