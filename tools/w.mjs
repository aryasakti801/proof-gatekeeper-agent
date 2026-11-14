import fs from 'fs';
import WCB from '../node_modules/circom_runtime/js/witness_calculator.js';
import { buildPoseidon } from 'circomlibjs';
const P = await buildPoseidon(); const F=P.F;
const wc = await WCB(fs.readFileSync('circuits/vfy-policy.wasm'));
export async function tryW(inp){ try{ const w=await wc.calculateWitness(inp,true); return {ok:true,w}; }catch(e){ return {ok:false,err:String(e.message).slice(0,300)} } }
const params=[1,2,3,4,5,6,7,8].map(String), salt='12345';
const h = (a)=>F.toString(P(a.map(BigInt)));
const base={matchId:'5',turnNumber:'3',selfBalance:'95',opponentBalance:'105',action:'0',amount:'0',circuitVersion:'1',salt,strategyParams:params};
for (const [name,c] of [['p9',h([...params,salt])],['saltfirst',h([salt,...params])],['p8',h(params)],['zero','0']]) {
  const r=await tryW({...base,commitment:c}); console.log(name, r.ok, r.err||'', r.ok? r.w.slice(0,12).map(String):'');
}
