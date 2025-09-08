// server.js — Express app for Render
import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import * as openpgp from 'openpgp';

const app = express();

// ===== CORS =====
app.use(cors({ origin: '*', methods: ['POST', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(bodyParser.json({ limit: '256kb' }));

// Allow secp256k1 if your key uses it (harmless for RSA keys)
try { openpgp?.config?.rejectCurves?.delete?.('secp256k1'); } catch (_) {}

function rfc3339UTC(date = new Date()) {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// ---- Your Base64 PGP public key directly here ----
const base64PublicKey = `
LS0tLS1CRUdJTiBQR1AgUFVCTElDIEtFWSBCTE9DSy0tLS0tClZlcnNpb246IEJDUEcgdjEuNjIKCm1FOEVhSDRnUGhNRks0RUVBQW9DQXdRQVNhR0ZEa0xSS29sMVA2TjhEQUpkMUt0SEpKKzR6NkNtVjM5bkRpQksKdE4wdEJiM3lZeGxHZkpWTmxlczFGRTVhd2NEdmF3OVJwOEkzZWcxZm5BQU50QUNJZEFRVEV3Z0FIQVVDYUg0ZwpQZ0liQXdZTENRZ0hBd0lHRlFnQ0NRb0xCQllDQXdFQUNna1FuRWxET3M0cFQ4SWJiUUVBMVdSTEhXOWY5RERUCmFqbDgyR3J2VHFxa2psYjZQYmVCeTJEWDZKcEd5ckVBL2lJbmVSblI0ejRKYmE3ejBqVDVQckhhYW5iTWVtUGkKYlJSZHpuczFPQjNzdUZNRWFINGdQaElGSzRFRUFBb0NBd1FBU2FHRkRrTFJLb2wxUDZOOERBSmQxS3RISkorNAp6NkNtVjM5bkRpQkt0TjB0QmIzeVl4bEdmSlZObGVzMUZFNWF3Y0R2YXc5UnA4STNlZzFmbkFBTkF3RUlCNGhuCkJCZ1RDQUFQQWhzTUJRa0paZ0dBQlFKb2ZpQStBQW9KRUp4SlF6ck9LVS9DODBFQS9qc1grTVExWFQ3OEIxSkkKN3QzTFNyL3JpSkppbmp4bGk0QmQwSHNtSHFMK0FQNHdDUmkxUmZZQUdvOGxWT29aZlBXZTErc2VJckxDRkJOTgovZ2lHUDZITXJRPT0KPWtWb20KLS0tLS1FTkQgUEdQIFBVQkxJQyBLRVkgQkxPQ0stLS0tLQo=
`.trim();

// Health
app.get('/health', (_req, res) => res.json({ status: 'ok', timeUTC: rfc3339UTC() }));

// POST /encrypt  ->  { encryptedCard, captureTime }
app.post('/encrypt', async (req, res) => {
  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const input = (body.cardData && typeof body.cardData === 'object') ? body.cardData : body;

    if (!input || typeof input !== 'object') {
      return res.status(400).json({ message: 'Invalid payload: expected JSON { cardData: { ... } }' });
    }

    // Only allowed fields
    const allowed = [
      'cardNumber', 'sequenceNumber', 'cardholderName',
      'startMonth', 'startYear', 'expiryMonth', 'expiryYear', 'cvv',
    ];
    const payload = {};
    for (const k of allowed) {
      if (input[k] !== undefined && input[k] !== null && String(input[k]) !== '') {
        payload[k] = String(input[k]);
      }
    }

    // Server capture time
    payload.captureTime = rfc3339UTC();

    // Decode Base64 → armored key text
    const armored = Buffer.from(base64PublicKey, 'base64').toString('utf8').trim();
    if (!armored.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
      return res.status(500).json({ message: 'BASE64_PUBLIC_KEY is not a valid armored PGP key' });
    }

    const publicKey = await openpgp.readKey({ armoredKey: armored });
    const message = await openpgp.createMessage({ text: JSON.stringify(payload) });

    // Encrypt → binary (Uint8Array), then base64
    const encryptedBinary = await openpgp.encrypt({
      message,
      encryptionKeys: publicKey,
      format: 'binary',
    });
    const encryptedCard = Buffer.from(encryptedBinary).toString('base64');

    return res.status(200).json({ encryptedCard, captureTime: payload.captureTime });
  } catch (err) {
    console.error('Encryption error:', err);
    return res.status(500).json({ message: 'Encryption failed', error: err?.message || String(err) });
  }
});

// Start (Render sets PORT env var)
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Encrypt server listening on :${PORT}`));
