const crypto = require('node:crypto');
const digest = (domain, payload) => crypto.createHash('sha256').update(domain + '\0' + payload).digest();
function createRecoveryApproval(data, oldID, userID, privateKey, now = Math.floor(Date.now()/1000)) {
  const payload = Buffer.from(JSON.stringify({contract:'shyvoting-reconcile-v1',scoping_id:data.scoping_id,identity_hash:data.identity_hash,
    old_submission_id:oldID,voter_pub_key:data.voter_pub_key,new_submission_nonce:data.new_submission_nonce,new_choices:data.new_choices || [],user_id:userID,expires_at:now+180})).toString('base64');
  return {payload,identity_signature:crypto.sign(null,digest('shyvoting-reconcile-identity-v1',payload),privateKey).toString('base64')};
}
function verifyRecoveryApproval(data, approval, identityKey, reconcileKey, now = Math.floor(Date.now()/1000)) {
  if (!approval || !reconcileKey || typeof approval.payload !== 'string' || approval.payload.length > 8192) throw Error('Missing recovery co-authorization');
  const message=JSON.parse(Buffer.from(approval.payload,'base64').toString('utf8'));
  if(message.contract !== 'shyvoting-reconcile-v1' || !Number.isSafeInteger(message.expires_at) || message.expires_at < now || message.expires_at > now+180 ||
    ['scoping_id','identity_hash','old_submission_id','voter_pub_key','new_submission_nonce'].some(field=>message[field] !== data[field]) ||
    JSON.stringify(message.new_choices) !== JSON.stringify(data.new_choices || [])) throw Error('Recovery scope mismatch');
  if(!crypto.verify(null,digest('shyvoting-reconcile-identity-v1',approval.payload),identityKey,Buffer.from(approval.identity_signature || '', 'base64')) ||
    !crypto.verify(null,digest('shyvoting-reconcile-v1',approval.payload),reconcileKey,Buffer.from(approval.reconciliation_signature || '', 'base64'))) throw Error('Invalid recovery co-authorization');
  return message;
}
function approvedBiometricDecision(decision) {
  const live=decision.liveness || decision.liveness_checks;
  const face=decision.face_match || decision.face_matches;
  const approved=entry=>Array.isArray(entry)?entry.length>0 && entry.every(x=>x.status==='Approved'):entry && entry.status==='Approved';
  return decision.status==='Approved' && approved(live) && approved(face);
}
module.exports={createRecoveryApproval,verifyRecoveryApproval,approvedBiometricDecision};
