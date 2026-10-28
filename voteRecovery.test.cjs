const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const Database=require('better-sqlite3');
const {installVoteRecovery,ownerHash,recoveryDeviceLabel}=require('./voteRecovery.cjs');
test('fresh biometric invocation authorizes a new key without replacing the original device',async()=>{
 const db=new Database(':memory:');
 db.exec('CREATE TABLE consumed_sessions(session_id TEXT,voter_pub_key TEXT,poll_id TEXT)');
 const original='1'.repeat(64),fresh='2'.repeat(64),participant='3'.repeat(64);
 db.prepare('INSERT INTO consumed_sessions VALUES (?,?,?)').run('enrollment',original,'poll');
 const handlers=new Map();const app={post:(path,fn)=>handlers.set(path,fn)};
 let biometric={status:'Approved',vendor_data:'alice',liveness:{status:'Approved'},face_match:{status:'Approved'}};
 const initial={status:'Approved',vendor_data:'alice',id_verification:{portrait_image:'https://provider.test/portrait'}};
 const key=crypto.generateKeyPairSync('ed25519');
 installVoteRecovery({app,db,authorize:()=>true,checkDiditSession:async id=>id==='enrollment'?initial:biometric,
 documentIdentityHash:()=>participant,extractFirebaseUidFromVendorData:d=>d.vendor_data,getObjectStorageClient:async()=>{throw Error('unexpected historical scan')},
 namespace:'test',bucket:'test',relayBaseURL:'https://relay.test',getApiKey:()=> 'test-key',privateKey:key.privateKey,workflowID:'biometric-workflow'});
 const originalFetch=global.fetch;
 global.fetch=async(url,options)=>{
  if(url==='https://provider.test/portrait')return new Response('reference-image');
  if(url==='https://verification.didit.me/v3/session/'){
   const body=JSON.parse(options.body);assert.equal(body.workflow_id,'biometric-workflow');assert.equal(body.portrait_image,Buffer.from('reference-image').toString('base64'));
   assert.equal(JSON.parse(body.vendor_data).userId,'alice');return Response.json({session_id:'fresh',url:'https://verify.didit.me/test'});
  }
  assert.equal(url,'https://relay.test/polls/poll/inspection');
  return Response.json({records:JSON.stringify({poll:{poll_id:'poll'},votes:[{ballot_id:'original-ballot',voter_pub_key_hash:ownerHash(original,'poll'),choices:['yes']}],voters:[{identity_hash:participant}]})});
 };
 const invoke=async(path,body)=>{
  const response={code:200,data:null,status(code){this.code=code;return this},json(data){this.data=data;return this}};
  await handlers.get(path)({body},response);return response;
 };
 try{
  const start=await invoke('/recovery/vote/start',{user_id:'alice',enrollment_session_id:'enrollment',scoping_id:'poll',voter_pub_key:fresh});
  assert.equal(start.code,200);assert.equal(start.data.session_id,'fresh');
  const data={scoping_id:'poll',identity_hash:participant,voter_pub_key:fresh,new_submission_nonce:'4'.repeat(64),new_choices:['no']};
  const input={user_id:'alice',session_id:'fresh',enrollment_session_id:'enrollment',old_submission_id:'',data};
  biometric={status:'Approved',vendor_data:'alice'};
  assert.equal((await invoke('/recovery/vote/authorize',input)).code,403);
  biometric={status:'Approved',vendor_data:'alice',liveness:{status:'Approved'},face_match:{status:'Approved'}};
  const approved=await invoke('/recovery/vote/authorize',input);assert.equal(approved.code,200);
  const payload=JSON.parse(Buffer.from(approved.data.payload,'base64').toString('utf8'));
  assert.equal(payload.old_submission_id,'original-ballot');assert.equal(payload.identity_hash,participant);
  assert.equal(db.prepare('SELECT voter_pub_key FROM consumed_sessions').get().voter_pub_key,original);
  const recovered=db.prepare('SELECT voter_pub_key,owner_hash,key_label FROM recovered_vote_devices').get();
  assert.equal(recovered.voter_pub_key,fresh);
  assert.equal(recovered.owner_hash,ownerHash(original,'poll'));
  assert.equal(recovered.key_label,recoveryDeviceLabel(fresh));
  assert.equal(recovered.key_label,fresh+'-freedom');
  assert.equal(payload.voter_pub_key,fresh);
  assert.equal(Object.hasOwn(payload,'key_label'),false);
  assert.equal(Object.hasOwn(approved.data,'key_label'),false);
  assert.equal((await invoke('/recovery/vote/authorize',{...input,data:{...data,new_submission_nonce:'5'.repeat(64)}})).code,428);
  assert.equal((await invoke('/recovery/vote/authorize',{...input,user_id:'someone-else'})).code,428);
  db.prepare('UPDATE vote_recovery_sessions SET created_at=?').run(Date.now()-16*60*1000);
  assert.equal((await invoke('/recovery/vote/authorize',input)).code,428);
 }finally{global.fetch=originalFetch;db.close()}
});

test('existing recovery registry gains labels without changing cryptographic fields',()=>{
 const db=new Database(':memory:');
 db.exec('CREATE TABLE recovered_vote_devices(poll_id TEXT NOT NULL,identity_hash TEXT NOT NULL,voter_pub_key TEXT NOT NULL,owner_hash TEXT NOT NULL,PRIMARY KEY(poll_id,identity_hash,voter_pub_key))');
 const key='a'.repeat(64),owner='b'.repeat(64);
 db.prepare('INSERT INTO recovered_vote_devices VALUES (?,?,?,?)').run('poll','identity',key,owner);
 const install=()=>installVoteRecovery({app:{post(){}},db});
 try{
  install();install();
  assert.deepEqual(db.prepare('SELECT * FROM recovered_vote_devices').get(),{
   poll_id:'poll',identity_hash:'identity',voter_pub_key:key,owner_hash:owner,key_label:key+'-freedom'
  });
 }finally{db.close()}
});
