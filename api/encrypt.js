import * as openpgp from 'openpgp';

const base64PublicKey = `
LS0tLS1CRUdJTiBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tClZlcnNpb246IEJDUEcgdjEuNjIKCm1FOEVhSDRnUGhNRks0RUVBQW9DQXdRQVNhR0ZEa0xSS29sMVA2TjhEQUpkMUt0SEpKKzR6NkNtVjM5bkRpQksKdE4wdEJiM3lZeGxHZkpWTmxlczFGRTVhd2NEdmF3OVJwOEkzZWcxZm5BQU50QUNJZEFRVEV3Z0FIQVVDYUg0ZwpQZ0liQXdZTENRZ0hBd0lHRlFnQ0NRb0xCQllDQXdFQUNna1FuRWxET3M0cFQ4SWJiUUVBMVdSTEhXOWY5RERUCmFqbDgyR3J2VHFxa2psYjZQYmVCeTJEWDZKcEd5ckVBL2lJbmVSblI0ejRKYmE3ejBqVDVQckhhYW5iTWVtUGkKYlJSZHpuczFPQjNzdUZNRWFINGdQaElGSzRFRUFBb0NBd1FBU2FHRkRrTFJLb2wxUDZOOERBSmQxS3RISkorNAp6NkNtVjM5bkRpQkt0TjB0QmIzeVl4bEdmSlZObGVzMUZFNWF3Y0R2YXc5UnA4STNlZzFmbkFBTkF3RUlCNGhuCkJCZ1RDQUFQQWhzTUJRa0paZ0dBQlFKb2ZpQStBQW9KRUp4SlF6ck9LVS9DODBFQS9qc1grTVExWFQ3OEIxSkkKN3QzTFNyL3JpSkppbmp4bGk0QmQwSHNtSHFMK0FQNHdDUmkxUmZZQUdvOGxWT29aZlBXZTErc2VJckxDRkJOTgovZ2lHUDZITXJRPT0KPWtWb20KLS0tLS1FTkQgUEdQIFBVQkxJQyBLRVkgQkxPQ0stLS0tLQo=
`.trim();

function rfc3339UTC(date = new Date()) {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export default async function handler(req, res) {
  // Allow cross-origin requests (important for frontend)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    try { openpgp?.config?.rejectCurves?.delete?.('secp256k1'); } catch (_) {}

    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const input = (body.cardData && typeof body.cardData === 'object') ? body.cardData : body;

    if (!input || typeof input !== 'object') {
      return res.status(400).json({ message: 'Invalid payload: expected JSON { cardData: { ... } }' });
    }

    // Only allow specific fields
    const allowed = ['cardNumber', 'sequenceNumber', 'cardholderName', 'startMonth', 'startYear', 'expiryMonth', 'expiryYear', 'cvv'];
    const payload = {};
    for (const k of allowed) {
      if (input[k] !== undefined && input[k] !== null && String(input[k]) !== '') {
        payload[k] = String(input[k]);
      }
    }

    payload.captureTime = rfc3339UTC();

    // Decode your base64 → armored key
    const armored = Buffer.from(base64PublicKey, 'base64').toString('utf8').trim();

    const publicKey = await openpgp.readKey({ armoredKey: armored });
    const message = await openpgp.createMessage({ text: JSON.stringify(payload) });

    const encryptedBinary = await openpgp.encrypt({ message, encryptionKeys: publicKey, format: 'binary' });
    const encryptedCard = Buffer.from(encryptedBinary).toString('base64');

    return res.status(200).json({ encryptedCard, captureTime: payload.captureTime });
  } catch (err) {
    return res.status(500).json({ message: 'Encryption failed', error: err?.message || String(err) });
  }
}
