const crypto = require('node:crypto');
const hex32 = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const key = value => crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(value, 'hex')]), format: 'der', type: 'spki' });
const fail = message => { throw new Error(message); };

function admissionFailureCode(error) {
  const codes = {
    'Invalid enrollment identity or device key': 'invalid_device_key',
    'Invalid nonce or stale ledger beacon': 'invalid_or_expired_beacon',
    'Unsupported submission identifier derivation': 'unsupported_derivation',
    'Invalid voter device signature': 'invalid_device_signature',
    'Invalid enrollment authority signature': 'invalid_enrollment_signature',
    'Invalid choices': 'invalid_choices',
    'Empty cast': 'empty_cast',
    'Duplicate cast': 'duplicate_cast',
    'Repeated verification session within a batch': 'duplicate_session',
    'Recovery target is absent': 'recovery_target_absent',
    'Update does not own an active ballot': 'update_owner_mismatch',
    'Replacement ballot ID already exists': 'replacement_exists',
    'Unsupported admission envelope': 'invalid_envelope',
  };
  return Object.hasOwn(codes, error?.message) ? codes[error.message] : 'admission_rejected';
}

function buildSeparatedRelease(snapshot, submissions, authorityPublicKey, beacons, now = Math.floor(Date.now() / 1000), reconciliationKey = null, recoveredDevices = []) {
  const records = JSON.parse(snapshot.records);
  const poll = records.poll;
  if (records.contract !== 'shyvoting-inspection-v1' || !poll?.poll_id || poll.status === 'closed' || now < poll.start_time || now >= poll.end_time) fail('Poll is not open');
  const expectedRoot = hash(Buffer.from('shyvoting-state-v2:poll:' + poll.poll_id + '\0' + snapshot.records));
  if (expectedRoot !== snapshot.records_root) fail('Snapshot commitment mismatch');
  if (!Array.isArray(submissions) || !submissions.length || submissions.length > 256) fail('Invalid admission batch');
  const ballots = new Map(records.votes.map(vote => [vote.ballot_id, { ...vote }]));
  const participants = new Map(records.voters.map(voter => [voter.identity_hash, { ...voter }]));
  if (ballots.size !== records.votes.length || participants.size !== records.voters.length || ballots.size !== participants.size) fail('Invalid two-list snapshot');
  let newEnrollments = 0;
  const usedSessions = new Set();
  for (const [submissionIndex, envelope] of submissions.entries()) {
    try {
    const data = envelope.data;
    if (![2, 6].includes(envelope.type) || data?.scoping_id !== poll.poll_id) fail('Unsupported admission envelope');
    if (!hex32(data.voter_pub_key) || !hex32(data.identity_hash)) fail('Invalid enrollment identity or device key');
    const nonce = envelope.type === 2 ? data.submission_nonce : data.new_submission_nonce;
    const choices = envelope.type === 2 ? data.choices : data.new_choices;
    if (!hex32(nonce) || !hex32(data.beacon_block_hash) || beacons[String(data.beacon_block_height)] !== data.beacon_block_hash) fail('Invalid nonce or stale ledger beacon');
    if (!['', undefined, 'nonce_only'].includes(data.submission_identifier_derivation)) fail('Unsupported submission identifier derivation');
    const deviceMessage = (envelope.type === 6 ? 'update:' : '') + nonce + ':' + poll.poll_id;
    if (!crypto.verify(null, Buffer.from(deviceMessage), key(data.voter_pub_key), Buffer.from(data.voter_sig || '', 'base64'))) fail('Invalid voter device signature');
    const enrollmentMessage = crypto.createHash('sha256').update(data.voter_pub_key + poll.poll_id + data.identity_hash).digest();
    if (!crypto.verify(null, enrollmentMessage, authorityPublicKey, Buffer.from(data.idv_attestation_sig || '', 'base64'))) fail('Invalid enrollment authority signature');
    if (!Array.isArray(choices) || new Set(choices).size !== choices.length || choices.some(choice => !poll.options.includes(choice)) || (choices.length && poll.voting_method === 'plurality' && choices.length !== 1)) fail('Invalid choices');
    const ballotID = hash(Buffer.concat([Buffer.from(data.beacon_block_hash, 'hex'), Buffer.from(nonce, 'hex')]));
    let owner = hash('partition-migration-auth:' + data.voter_pub_key + ':' + poll.poll_id);
    if (envelope.type === 6 && !data.recovery_authorization) {
      const recovered = recoveredDevices.find(device => device.identity_hash === data.identity_hash && device.voter_pub_key === data.voter_pub_key);
      const target = ballots.get(data.old_submission_id) || ballots.get(ballotID);
      // Supplemental authorization must not override the original device's ownership.
      if (recovered && target?.voter_pub_key_hash !== owner) owner = recovered.owner_hash;
    }
    if (envelope.type === 6 && data.recovery_authorization) {
      require('./recoveryAuthorizations.cjs').verifyRecoveryApproval(data, data.recovery_authorization, authorityPublicKey, reconciliationKey, now);
      const previous = ballots.get(data.old_submission_id) || ballots.get(ballotID);
      if (!previous) fail('Recovery target is absent');
      owner = previous.voter_pub_key_hash;
    }
    if (envelope.type === 2) {
      if (!choices.length) fail('Empty cast');
      const existing = ballots.get(ballotID);
      if (existing && participants.has(data.identity_hash) && existing.voter_pub_key_hash === owner && JSON.stringify(existing.choices) === JSON.stringify(choices)) continue;
      if (participants.has(data.identity_hash) || existing) fail('Duplicate cast');
      if (data.didit_session_id) {
        if (usedSessions.has(data.didit_session_id)) fail('Repeated verification session within a batch');
        usedSessions.add(data.didit_session_id);
      }
      newEnrollments++;
    } else {
      const existing = ballots.get(ballotID);
      if (choices.length && existing && participants.has(data.identity_hash) && existing.voter_pub_key_hash === owner && JSON.stringify(existing.choices) === JSON.stringify(choices)) continue;
      const old = ballots.get(data.old_submission_id);
      if (!choices.length && !old && !participants.has(data.identity_hash)) continue;
      if (!old || old.voter_pub_key_hash !== owner || !participants.has(data.identity_hash)) fail('Update does not own an active ballot');
      if (ballotID !== data.old_submission_id && ballots.has(ballotID)) fail('Replacement ballot ID already exists');
      ballots.delete(data.old_submission_id);
      if (!choices.length) { participants.delete(data.identity_hash); continue; }
    }
    ballots.set(ballotID, { ballot_id: ballotID, choices: [...choices], voter_pub_key_hash: owner });
    participants.set(data.identity_hash, { identity_hash: data.identity_hash });
    } catch (error) { error.submissionIndex = submissionIndex; throw error; }
  }
  if (ballots.size !== participants.size) fail('Admission broke count-match');
  const release = { contract: 'shyvoting-separated-release-v1', scoping_id: poll.poll_id, expected_records_root: expectedRoot,
    ballots: [...ballots.values()].sort((a, b) => a.ballot_id.localeCompare(b.ballot_id)),
    participants: [...participants.values()].sort((a, b) => a.identity_hash.localeCompare(b.identity_hash)), new_enrollments: newEnrollments };
  return release;
}

function signSeparatedRelease(release, privateKey) {
  const data = JSON.stringify(release);
  const message = crypto.createHash('sha256').update('shyvoting-separated-release-v1\0').update(data).digest();
  return { type: 12, data: release, signature: crypto.sign(null, message, privateKey).toString('base64') };
}

module.exports = { buildSeparatedRelease, signSeparatedRelease, admissionFailureCode };
