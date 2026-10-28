const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {createRecoveryApproval,verifyRecoveryApproval,approvedBiometricDecision}=require('./recoveryAuthorizations.cjs');
const {buildSeparatedRelease}=require('./separatedPublication.cjs');
const hash=value=>crypto.createHash('sha256').update(value).digest('hex');
const identity=crypto.generateKeyPairSync('ed25519'),reconcile=crypto.generateKeyPairSync('ed25519');
const original=crypto.generateKeyPairSync('ed25519'),replacement=crypto.generateKeyPairSync('ed25519');
const pub=key=>key.publicKey.export({type:'spki',format:'der'}).subarray(-32).toString('hex');
const poll={poll_id:'poll',options:['yes','no'],voting_method:'plurality',status:'open',start_time:0,end_time:9999};
const voterID='b'.repeat(64),beacon='c'.repeat(64),originalOwner=hash('partition-migration-auth:'+pub(original)+':poll');
function state(ballots){const records=JSON.stringify({contract:'shyvoting-inspection-v1',poll,votes:ballots,voters:[{identity_hash:voterID}]});return{records,records_root:hash('shyvoting-state-v2:poll:poll\0'+records)}}
function update(key,old,nonce,choices){const p=pub(key);return{type:6,data:{scoping_id:'poll',identity_hash:voterID,old_submission_id:old,new_submission_nonce:nonce,new_choices:choices,beacon_block_hash:beacon,beacon_block_height:1,voter_pub_key:p,voter_sig:crypto.sign(null,Buffer.from('update:'+nonce+':poll'),key.privateKey).toString('base64'),idv_attestation_sig:crypto.sign(null,crypto.createHash('sha256').update(p+'poll'+voterID).digest(),identity.privateKey).toString('base64')}}}
function approval(data){const a=createRecoveryApproval(data,data.old_submission_id,'user',identity.privateKey,100);a.reconciliation_signature=crypto.sign(null,crypto.createHash('sha256').update('shyvoting-reconcile-v1\0'+a.payload).digest(),reconcile.privateKey).toString('base64');return a}
test('keyless recovery adds a device without replacing original ownership or duplicating participation',()=>{
 const first=state([{ballot_id:'old',choices:['yes'],voter_pub_key_hash:originalOwner}]);
 const fresh=update(replacement,'old','a'.repeat(64),['no']);
 assert.throws(()=>buildSeparatedRelease(first,[fresh],identity.publicKey,{'1':beacon},100),/own/);
 fresh.data.recovery_authorization=approval(fresh.data);
 const next=buildSeparatedRelease(first,[fresh],identity.publicKey,{'1':beacon},100,reconcile.publicKey);
 assert.equal(next.ballots.length,1);assert.equal(next.participants.length,1);assert.equal(next.ballots[0].voter_pub_key_hash,originalOwner);
 const fromOriginal=update(original,next.ballots[0].ballot_id,'d'.repeat(64),['yes']);
 const again=buildSeparatedRelease(state(next.ballots),[fromOriginal],identity.publicKey,{'1':beacon},100);
 const fromNew=update(replacement,again.ballots[0].ballot_id,'e'.repeat(64),[]);
 const last=buildSeparatedRelease(state(again.ballots),[fromNew],identity.publicKey,{'1':beacon},100,reconcile.publicKey,[{identity_hash:voterID,voter_pub_key:pub(replacement),owner_hash:originalOwner}]);
 const labeled=buildSeparatedRelease(state(again.ballots),[fromNew],identity.publicKey,{'1':beacon},100,reconcile.publicKey,[{identity_hash:voterID,voter_pub_key:pub(replacement),owner_hash:originalOwner,key_label:pub(replacement)+'-freedom'}]);
 assert.deepEqual(labeled,last);
 assert.throws(()=>buildSeparatedRelease(state(again.ballots),[fromNew],identity.publicKey,{'1':beacon},100,reconcile.publicKey,[{identity_hash:voterID,voter_pub_key:pub(replacement)+'-freedom',owner_hash:originalOwner}]),/own/);
 assert.equal(last.ballots.length,0);assert.equal(last.participants.length,0);
 assert.equal(JSON.stringify(next).includes('recovery_authorization'),false);
});
test('recovery rejects missing co-signature, expired proof and altered action scope',()=>{
 const data=update(replacement,'old','a'.repeat(64),['no']).data;const a=approval(data);
 assert.doesNotThrow(()=>verifyRecoveryApproval(data,a,identity.publicKey,reconcile.publicKey,100));
 assert.throws(()=>verifyRecoveryApproval(data,{...a,reconciliation_signature:''},identity.publicKey,reconcile.publicKey,100),/co-authorization/);
 assert.throws(()=>verifyRecoveryApproval(data,a,identity.publicKey,reconcile.publicKey,281),/scope/);
 assert.throws(()=>verifyRecoveryApproval({...data,new_choices:[]},a,identity.publicKey,reconcile.publicKey,100),/scope/);
 assert.throws(()=>verifyRecoveryApproval({...data,identity_hash:'f'.repeat(64)},a,identity.publicKey,reconcile.publicKey,100),/scope/);
});
test('biometric recovery requires explicit liveness and face-match approval',()=>{
 assert.equal(Boolean(approvedBiometricDecision({status:'Approved'})),false);
 assert.equal(Boolean(approvedBiometricDecision({status:'Approved',liveness_checks:[],face_matches:[]})),false);
 assert.equal(Boolean(approvedBiometricDecision({status:'Approved',liveness:{status:'Approved'},face_match:{status:'Approved'}})),true);
 assert.equal(Boolean(approvedBiometricDecision({status:'Approved',liveness_checks:[{status:'Approved'}],face_matches:[{status:'Declined'}]})),false);
});
