import * as openpgp from 'openpgp';

const base64PublicKey = api/encrypt.js

function rfc3339UTC(d = new Date()) {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function json(status, data = {}) {
  return {
    statusCode: status,
    headers: {
      'Access-Control-Allow-Origin': '*',      // tighten to your domain later
      'Access-Control-Allow-Methods': 'POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    },
    body: JSON.stringify(data)
  };
}

export async function handler(event) {
  if (event.httpMethod === 'OPTIONS') return json(200, {});
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });

  try {
    try { openpgp?.config?.rejectCurves?.delete?.('secp256k1'); } catch (_) {}

    const body = event.body ? JSON.parse(event.body) : {};
    const input = (body.cardData && typeof body.cardData === 'object') ? body.cardData : body;

    if (!input || typeof input !== 'object') {
      return json(400, { message: 'Invalid payload: expected JSON { cardData: { ... } }' });
    }

    const allowed = ['cardNumber','sequenceNumber','cardholderName','startMonth','startYear','expiryMonth','expiryYear','cvv'];
    const payload = {};
    for (const k of allowed) {
      if (input[k] !== undefined && input[k] !== null && String(input[k]) !== '') payload[k] = String(input[k]);
    }

    payload.captureTime = rfc3339UTC();

    const armored = Buffer.from(base64PublicKey, 'base64').toString('utf8').trim();
    if (!armored.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
      return json(500, { message: 'Base64 key is not a valid armored PGP key' });
    }

    const publicKey = await openpgp.readKey({ armoredKey: armored });
    const message   = await openpgp.createMessage({ text: JSON.stringify(payload) });
    const encryptedBinary = await openpgp.encrypt({ message, encryptionKeys: publicKey, format: 'binary' });
    const encryptedCard   = Buffer.from(encryptedBinary).toString('base64');

    return json(200, { encryptedCard, captureTime: payload.captureTime });
  } catch (err) {
    return json(500, { message: 'Encryption failed', error: err?.message || String(err) });
  }
}
