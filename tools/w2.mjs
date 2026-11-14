import fs from 'fs';
import WCB from '../node_modules/circom_runtime/js/witness_calculator.js';
import { buildPoseidon } from 'circomlibjs';
const P = await buildPoseidon(); const F=P.F;
const buf=fs.readFileSync('circuits/vfy-policy.wasm');
const h = (a)=>F.toString(P(a.map(BigInt)));
const origErr=console.error; 
export async function valid(params, st){
  const salt='777'; const commitment=h([...params,salt]); const out=[];
  for (let a=0;a<3;a++) for (let n=0;n<=12;n++){ if(a!==2&&n>0) break;
    const wc=await WCB(buf); console.error=()=>{};
    try{ const w=await wc.calculateWitness({commitment,matchId:'5',turnNumber:String(st.t),selfBalance:String(st.s),opponentBalance:String(st.o),action:String(a),amount:String(n),circuitVersion:'1',salt,strategyParams:params.map(String)},true); out.push(a===2?'X'+n:(a?'F':'H')); }catch(e){}
    console.error=origErr; }
  return out;
}
const tests=JSON.parse(process.argv[2]);
for (const [p,st] of tests) console.log(JSON.stringify(p), JSON.stringify(st), (await valid(p,st)).join(' '));
