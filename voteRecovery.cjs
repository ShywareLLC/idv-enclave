const crypto=require('node:crypto');
const {createRecoveryApproval,approvedBiometricDecision}=require('./recoveryAuthorizations.cjs');
const recoveryDeviceLabel=key=>key+'-freedom';
const ownerHash=(key,poll)=>crypto.createHash('sha256').update('partition-migration-auth:'+key+':'+poll).digest('hex');
async function streamBytes(stream,maximum){let chunks=[],size=0;for await(const chunk of stream){const b=Buffer.from(chunk);size+=b.length;if(size>maximum)throw Error('Provider record too large');chunks.push(b)}return Buffer.concat(chunks)}
function installVoteRecovery({app,db,authorize,checkDiditSession,documentIdentityHash,extractFirebaseUidFromVendorData,getObjectStorageClient,namespace,bucket,relayBaseURL,getApiKey,privateKey,workflowID}) {
 db.exec(`CREATE TABLE IF NOT EXISTS vote_recovery_sessions(session_id TEXT PRIMARY KEY,enrollment_session_id TEXT NOT NULL,poll_id TEXT NOT NULL,voter_pub_key TEXT NOT NULL,user_id TEXT NOT NULL,created_at INTEGER NOT NULL,operation_hash TEXT);
 CREATE TABLE IF NOT EXISTS recovered_vote_devices(poll_id TEXT NOT NULL,identity_hash TEXT NOT NULL,voter_pub_key TEXT NOT NULL,owner_hash TEXT NOT NULL,key_label TEXT NOT NULL,PRIMARY KEY(poll_id,identity_hash,voter_pub_key));
 CREATE TABLE IF NOT EXISTS authorized_vote_devices(poll_id TEXT NOT NULL,identity_hash TEXT NOT NULL,voter_pub_key TEXT NOT NULL,PRIMARY KEY(poll_id,identity_hash,voter_pub_key));`);
 if(!db.prepare('PRAGMA table_info(recovered_vote_devices)').all().some(column=>column.name==='key_label')){
  db.transaction(()=>{
   db.exec("ALTER TABLE recovered_vote_devices ADD COLUMN key_label TEXT NOT NULL DEFAULT ''");
   db.prepare("UPDATE recovered_vote_devices SET key_label=voter_pub_key || '-freedom'").run();
  })();
 }
 async function identity(enrollment,user,poll){const d=await checkDiditSession(enrollment);if(d.status!=='Approved'||extractFirebaseUidFromVendorData(d)!==user)throw Error('Identity authentication failed');return {decision:d,hash:documentIdentityHash(d,poll)}}
 app.post('/recovery/vote/start',async(req,res)=>{
  if(!authorize(req))return res.status(401).json({error:'unauthorized'});
  const {user_id,enrollment_session_id,scoping_id,voter_pub_key}=req.body||{};
  if(!user_id||!enrollment_session_id||!scoping_id||!/^[0-9a-f]{64}$/.test(voter_pub_key||'')||!workflowID)return res.status(503).json({error:'Biometric recovery is unavailable'});
  try{
   const verified=await identity(enrollment_session_id,user_id,scoping_id);
   const portrait=verified.decision.id_verification?.portrait_image || verified.decision.id_verification?.portrait_image_url;
   if(typeof portrait!=='string'||!portrait.startsWith('https://'))return res.status(409).json({error:'Enrollment portrait is unavailable for biometric recovery'});
   const image=await fetch(portrait,{signal:AbortSignal.timeout(10000),redirect:'error'});
   if(!image.ok)throw Error('Enrollment portrait unavailable');
   const bytes=await streamBytes(image.body,1024*1024);
   const challenge=crypto.randomBytes(32).toString('hex');
   const response=await fetch('https://verification.didit.me/v3/session/',{method:'POST',headers:{'x-api-key':getApiKey(),'Content-Type':'application/json'},body:JSON.stringify({workflow_id:workflowID,portrait_image:bytes.toString('base64'),callback:'https://youinpolitics.com/verification-complete',vendor_data:JSON.stringify({userId:user_id,purpose:'vote_reconcile',challenge})}),signal:AbortSignal.timeout(15000)});
   if(!response.ok)throw Error('Biometric session creation unavailable');
   const session=await response.json();const sessionID=session.session_id;const url=session.url||session.session_url;
   if(typeof sessionID!=='string'||typeof url!=='string'||!url.startsWith('https://'))throw Error('Invalid biometric session');
   db.prepare('DELETE FROM vote_recovery_sessions WHERE created_at < ?').run(Date.now()-15*60*1000);
   db.prepare('INSERT INTO vote_recovery_sessions(session_id,enrollment_session_id,poll_id,voter_pub_key,user_id,created_at) VALUES (?,?,?,?,?,?)').run(sessionID,enrollment_session_id,scoping_id,voter_pub_key,user_id,Date.now());
   res.json({session_id:sessionID,url});
  }catch{return res.status(503).json({error:'Biometric recovery is temporarily unavailable'})}
 });
 async function historicalTarget(verified,poll,enrollment,records){
  const keys=new Set(db.prepare('SELECT voter_pub_key FROM authorized_vote_devices WHERE poll_id=? AND identity_hash=?').all(poll,verified.hash).map(r=>r.voter_pub_key));
  for(const r of db.prepare('SELECT voter_pub_key FROM consumed_sessions WHERE session_id=? AND poll_id=?').all(enrollment,poll))keys.add(r.voter_pub_key);
  let matches=records.votes.filter(v=>[...keys].some(key=>ownerHash(key,poll)===v.voter_pub_key_hash));
  if(matches.length===1)return matches[0].ballot_id;
  const client=await getObjectStorageClient();const listing=await client.listObjects({namespaceName:namespace,bucketName:bucket,prefix:'attest-requests/',limit:1000});
  const files=(listing.listObjects?.objects||[]).slice(-200);
  for(let offset=0;offset<files.length;offset+=10){
   const events=await Promise.all(files.slice(offset,offset+10).map(async object=>{
    const response=await client.getObject({namespaceName:namespace,bucketName:bucket,objectName:object.name});
    return JSON.parse((await streamBytes(response.value,65536)).toString('utf8'));
   }));
   for(const event of events){
    if(event.outcome==='signed'&&event.poll_id===poll&&event.identityHash===verified.hash&&/^[0-9a-f]{64}$/.test(event.voter_pub_key||'')){
     db.prepare('INSERT OR IGNORE INTO authorized_vote_devices(poll_id,identity_hash,voter_pub_key) VALUES (?,?,?)').run(poll,verified.hash,event.voter_pub_key);keys.add(event.voter_pub_key);
    }
   }
  }
  matches=records.votes.filter(v=>[...keys].some(key=>ownerHash(key,poll)===v.voter_pub_key_hash));
  if(matches.length!==1)throw Error('Protected recovery linkage unavailable');return matches[0].ballot_id;
 }
 app.post('/recovery/vote/authorize',async(req,res)=>{
  if(!authorize(req))return res.status(401).json({error:'unauthorized'});
  const {user_id,session_id,enrollment_session_id,data}=req.body||{};
  try{
   const row=db.prepare('SELECT * FROM vote_recovery_sessions WHERE session_id=?').get(session_id);
   if(!row||row.user_id!==user_id||row.enrollment_session_id!==enrollment_session_id||row.poll_id!==data?.scoping_id||row.voter_pub_key!==data?.voter_pub_key||Date.now()-row.created_at>15*60*1000)return res.status(428).json({error:'Fresh biometric recovery verification is required'});
   const decision=await checkDiditSession(session_id);
   if(!approvedBiometricDecision(decision)||extractFirebaseUidFromVendorData(decision)!==user_id)return res.status(403).json({error:'Biometric recovery verification did not pass'});
   const verified=await identity(enrollment_session_id,user_id,data.scoping_id);
   if(verified.hash!==data.identity_hash)return res.status(403).json({error:'Recovery identity mismatch'});
   const snapshotResponse=await fetch(relayBaseURL.replace(/\/$/,'')+'/polls/'+encodeURIComponent(data.scoping_id)+'/inspection',{signal:AbortSignal.timeout(10000)});
   if(!snapshotResponse.ok)throw Error('Snapshot unavailable');const snapshot=await snapshotResponse.json();const records=JSON.parse(snapshot.records);
   if(!records.voters.some(v=>v.identity_hash===verified.hash))return res.status(404).json({error:'No active vote exists for this participant'});
   const oldID=req.body.old_submission_id||await historicalTarget(verified,data.scoping_id,enrollment_session_id,records);
   if(!records.votes.some(v=>v.ballot_id===oldID))return res.status(409).json({error:'Recovery target changed; retry'});
   const operationHash=crypto.createHash('sha256').update(JSON.stringify({poll:data.scoping_id,oldID,nonce:data.new_submission_nonce,choices:data.new_choices})).digest('hex');
   if(row.operation_hash&&row.operation_hash!==operationHash)return res.status(428).json({error:'A new biometric verification is required for this operation'});
   db.prepare('UPDATE vote_recovery_sessions SET operation_hash=? WHERE session_id=?').run(operationHash,session_id);
   db.prepare('INSERT OR IGNORE INTO authorized_vote_devices(poll_id,identity_hash,voter_pub_key) VALUES (?,?,?)').run(data.scoping_id,verified.hash,data.voter_pub_key);
   const owner=records.votes.find(v=>v.ballot_id===oldID).voter_pub_key_hash;
   db.prepare('INSERT OR IGNORE INTO recovered_vote_devices(poll_id,identity_hash,voter_pub_key,owner_hash,key_label) VALUES (?,?,?,?,?)').run(data.scoping_id,verified.hash,data.voter_pub_key,owner,recoveryDeviceLabel(data.voter_pub_key));
   return res.json(createRecoveryApproval(data,oldID,user_id,privateKey));
  }catch{return res.status(503).json({error:'Protected recovery lookup is temporarily unavailable'})}
 });
}
module.exports={installVoteRecovery,ownerHash,recoveryDeviceLabel};
