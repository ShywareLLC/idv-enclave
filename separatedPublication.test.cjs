const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { buildSeparatedRelease, signSeparatedRelease } = require('./separatedPublication.cjs');
const authority = crypto.generateKeyPairSync('ed25519');
const device = crypto.generateKeyPairSync('ed25519');
const voter = device.publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('hex');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const identity = 'b'.repeat(64), beacon = 'c'.repeat(64);
const poll = {poll_id:'poll',options:['yes','no'],voting_method:'plurality',status:'open',start_time:0,end_time:9999999999};
function snapshot(votes=[],voters=[]) {
 const records=JSON.stringify({contract:'shyvoting-inspection-v1',poll,votes,voters});
 return {records,records_root:hash('shyvoting-state-v2:poll:poll\0'+records)};
}
function input(type,choices,nonce='a'.repeat(64),old) {
 const data={scoping_id:'poll',voter_pub_key:voter,identity_hash:identity,beacon_block_hash:beacon,beacon_block_height:1,
  idv_attestation_sig:crypto.sign(null,crypto.createHash('sha256').update(voter+'poll'+identity).digest(),authority.privateKey).toString('base64')};
 if(type===2)Object.assign(data,{submission_nonce:nonce,choices});
 else Object.assign(data,{new_submission_nonce:nonce,new_choices:choices,old_submission_id:old});
 data.voter_sig=crypto.sign(null,Buffer.from((type===6?'update:':'')+nonce+':poll'),device.privateKey).toString('base64');
 return {type,data};
}
const build=(state,inputs)=>buildSeparatedRelease(state,inputs,authority.publicKey,{'1':beacon},100);

test('admission diagnostics expose only fixed predicate codes',()=>{
 const {admissionFailureCode}=require('./separatedPublication.cjs');
 assert.equal(admissionFailureCode(new Error('Update does not own an active ballot')),'update_owner_mismatch');
 assert.equal(admissionFailureCode(new Error('Invalid nonce or stale ledger beacon')),'invalid_or_expired_beacon');
 assert.equal(admissionFailureCode(new Error('private voter payload')),'admission_rejected');
 assert.equal(admissionFailureCode(new Error('toString')),'admission_rejected');
});

test('cast, replace, withdraw and retry preserve independent lists',()=>{
 const cast=input(2,['yes']);const first=build(snapshot(),[cast]);
 assert.equal(first.ballots.length,1);assert.equal(first.participants.length,1);
 const state=snapshot(first.ballots,first.participants);
 assert.equal(build(state,[cast]).new_enrollments,0);
 const next=build(state,[input(6,['no'],'d'.repeat(64),first.ballots[0].ballot_id)]);
 assert.deepEqual(next.ballots[0].choices,['no']);assert.equal(next.participants[0].identity_hash,identity);
 const last=build(snapshot(next.ballots,next.participants),[input(6,[],'e'.repeat(64),next.ballots[0].ballot_id)]);
 assert.deepEqual(last.ballots,[]);assert.deepEqual(last.participants,[]);
 const wire=signSeparatedRelease(first,authority.privateKey);
 assert.equal(crypto.verify(null,crypto.createHash('sha256').update('shyvoting-separated-release-v1\0').update(JSON.stringify(wire.data)).digest(),authority.publicKey,Buffer.from(wire.signature,'base64')),true);
 const serialized=JSON.stringify(wire);
 for(const field of ['submission_nonce','voter_pub_key"','voter_sig','idv_attestation_sig','didit_session_id','old_submission_id'])assert.equal(serialized.includes(field),false,field);
});

test('gate rejects forged authorization, stale entropy, wrong ownership and invalid choices',()=>{
 const altered=input(2,['yes']);altered.data.voter_sig=Buffer.alloc(64).toString('base64');
 assert.throws(()=>build(snapshot(),[altered]),/device signature/);
 const stale=input(2,['yes']);stale.data.beacon_block_height=2;assert.throws(()=>build(snapshot(),[stale]),/beacon/);
 assert.throws(()=>build(snapshot(),[input(2,['invalid'])]),/choices/);
 const first=build(snapshot(),[input(2,['yes'])]);first.ballots[0].voter_pub_key_hash='f'.repeat(64);
 assert.throws(()=>build(snapshot(first.ballots,first.participants),[input(6,['no'],'d'.repeat(64),first.ballots[0].ballot_id)]),/own/);
});

test('stale supplemental authorization cannot override canonical device ownership',()=>{
 const first=build(snapshot(),[input(2,['yes'])]);
 const state=snapshot(first.ballots,first.participants);
 const stale=[{identity_hash:identity,voter_pub_key:voter,owner_hash:'f'.repeat(64)}];
 const update=input(6,['no'],'d'.repeat(64),first.ballots[0].ballot_id);
 const release=buildSeparatedRelease(state,[update],authority.publicKey,{'1':beacon},100,null,stale);
 assert.deepEqual(release.ballots[0].choices,['no']);
 assert.equal(release.ballots[0].voter_pub_key_hash,first.ballots[0].voter_pub_key_hash);
 assert.deepEqual(release.participants,first.participants);
 const retried=buildSeparatedRelease(snapshot(release.ballots,release.participants),[update],authority.publicKey,{'1':beacon},100,null,stale);
 assert.deepEqual(retried.ballots,release.ballots);
 const withdrawn=buildSeparatedRelease(state,[input(6,[],'e'.repeat(64),first.ballots[0].ballot_id)],authority.publicKey,{'1':beacon},100,null,stale);
 assert.deepEqual(withdrawn.ballots,[]);
 assert.deepEqual(withdrawn.participants,[]);
 const wrong=JSON.parse(JSON.stringify(first.ballots));wrong[0].voter_pub_key_hash='1'.repeat(64);
 assert.throws(()=>buildSeparatedRelease(snapshot(wrong,first.participants),[update],authority.publicKey,{'1':beacon},100,null,stale),/own/);
});

test('mixed cast/change/withdraw batch is atomic, retryable and reports the failing index',()=>{
 const other=crypto.generateKeyPairSync('ed25519');
 const otherPub=other.publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('hex');
 const otherIdentity='1'.repeat(64);
 function otherInput(type,choices,nonce,old){
  const envelope=input(type,choices,nonce,old),data=envelope.data;
  data.voter_pub_key=otherPub;data.identity_hash=otherIdentity;
  data.idv_attestation_sig=crypto.sign(null,crypto.createHash('sha256').update(otherPub+'poll'+otherIdentity).digest(),authority.privateKey).toString('base64');
  data.voter_sig=crypto.sign(null,Buffer.from((type===6?'update:':'')+nonce+':poll'),other.privateKey).toString('base64');
  return envelope;
 }
 const first=build(snapshot(),[input(2,['yes'])]);
 const replace=input(6,['no'],'d'.repeat(64),first.ballots[0].ballot_id);
 const castOther=otherInput(2,['yes'],'2'.repeat(64));
 const mixed=build(snapshot(first.ballots,first.participants),[replace,castOther]);
 assert.equal(mixed.ballots.length,2);assert.equal(mixed.participants.length,2);
 const retried=build(snapshot(mixed.ballots,mixed.participants),[replace,castOther]);
 assert.deepEqual(retried.ballots,mixed.ballots);assert.equal(retried.new_enrollments,0);
 const otherBallot=hash(Buffer.concat([Buffer.from(beacon,'hex'),Buffer.from('2'.repeat(64),'hex')]));
 const withdraw=otherInput(6,[],'3'.repeat(64),otherBallot);
 const last=build(snapshot(mixed.ballots,mixed.participants),[withdraw]);
 assert.equal(last.ballots.length,1);assert.equal(last.participants.length,1);
 assert.deepEqual(build(snapshot(last.ballots,last.participants),[withdraw]).ballots,last.ballots);
 const invalid=otherInput(2,['bad'],'4'.repeat(64));
 assert.throws(()=>build(snapshot(first.ballots,first.participants),[replace,invalid]),error=>error.submissionIndex===1);
 assert.deepEqual(first.ballots[0].choices,['yes']);
});
