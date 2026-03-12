const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const SUPERDISPATCH_URL =
  process.env.SUPERDISPATCH_PRICING_URL ||
  'https://pricing-insights.superdispatch.com/api/v1/recommended-price';

const API_KEY = process.env.SUPERDISPATCH_API_KEY;
const APP_USERNAME = process.env.APP_USERNAME;
const APP_PASSWORD = process.env.APP_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret';

let rucaData = {};
try {
  const rucaPath = path.join(__dirname, 'ruca_by_zip.json');
  rucaData = JSON.parse(fs.readFileSync(rucaPath, 'utf8'));
  console.log('RUCA data loaded:', Object.keys(rucaData).length, 'ZIP codes');
} catch (err) {
  console.error('Failed to load RUCA file:', err);
}

function rucaCategory(code) {
  if (code === undefined || code === null || code === '') return 'Unknown';
  const n = Number(code);
  if (n >= 1 && n <= 3) return 'Metro';
  if (n >= 4 && n <= 6) return 'Suburban / Small City';
  if (n >= 7 && n <= 9) return 'Rural';
  if (n === 10) return 'Very Remote';
  return 'Unknown';
}

function calculateLaneDifficulty(pickupCategory, dropoffCategory) {
  const p = (pickupCategory || '').trim();
  const d = (dropoffCategory || '').trim();
  if (!p || !d || p === 'Unknown' || d === 'Unknown') return 'Unknown';
  if (p === 'Very Remote' || d === 'Very Remote') return 'Very Hard';
  if (p === 'Rural' || d === 'Rural') return 'Hard';
  if (p === 'Metro' && d === 'Metro') return 'Easy';
  return 'Standard';
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = {};
  header.split(';').forEach((part) => {
    const [key, ...rest] = part.trim().split('=');
    if (!key) return;
    cookies[key] = decodeURIComponent(rest.join('='));
  });
  return cookies;
}

function signSession(username) {
  const payload = JSON.stringify({ username, exp: Date.now() + 1000 * 60 * 60 * 12 });
  const payloadBase64 = Buffer.from(payload).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payloadBase64).digest('base64url');
  return `${payloadBase64}.${sig}`;
}

function verifySession(token) {
  if (!token || !token.includes('.')) return null;
  const [payloadBase64, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', SESSION_SECRET).update(payloadBase64).digest('base64url');
  if (sig !== expectedSig) return null;
  try {
    const payload = JSON.parse(Buffer.from(payloadBase64, 'base64url').toString('utf8'));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const cookies = parseCookies(req);
  const session = verifySession(cookies.auth_session);
  if (!session) return res.redirect('/login');
  req.user = session;
  next();
}

async function lookupZipDetails(zip) {
  const cleanZip = String(zip || '').replace(/\D/g, '').slice(0, 5);
  if (cleanZip.length !== 5) throw new Error('ZIP must be 5 digits');
  const response = await fetch(`https://api.zippopotam.us/us/${cleanZip}`);
  if (!response.ok) throw new Error('ZIP lookup failed');
  const data = await response.json();
  const place = data.places && data.places[0] ? data.places[0] : null;
  if (!place) throw new Error('ZIP lookup returned no places');
  return {
    zip: cleanZip,
    city: place['place name'] || '',
    state: place['state abbreviation'] || '',
    latitude: Number(place.latitude),
    longitude: Number(place.longitude)
  };
}

function haversineMiles(lat1, lon1, lat2, lon2) {
  const R = 3958.8;
  const toRad = (deg) => (deg * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function estimateRoadMiles(fromZip, toZip) {
  const crowMiles = haversineMiles(fromZip.latitude, fromZip.longitude, toZip.latitude, toZip.longitude);
  return Math.max(1, Math.round(crowMiles * 1.18));
}

app.get('/login', (req, res) => {
  const session = verifySession(parseCookies(req).auth_session);
  if (session) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/login', (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  if (!APP_USERNAME || !APP_PASSWORD) {
    return res.status(500).send('Server auth environment variables are not configured.');
  }
  if (username !== APP_USERNAME || password !== APP_PASSWORD) {
    return res.redirect('/login?error=1');
  }
  const isProduction = process.env.NODE_ENV === 'production';
  res.setHeader(
    'Set-Cookie',
    `auth_session=${encodeURIComponent(signSession(username))}; HttpOnly; Path=/; SameSite=Lax; Max-Age=43200${isProduction ? '; Secure' : ''}`
  );
  res.redirect('/');
});

app.post('/logout', (req, res) => {
  const isProduction = process.env.NODE_ENV === 'production';
  res.setHeader(
    'Set-Cookie',
    `auth_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${isProduction ? '; Secure' : ''}`
  );
  res.redirect('/login');
});

app.get('/health', (req, res) => res.type('text/plain').send('OK'));
app.get('/', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/session', requireAuth, (req, res) => res.json({ authenticated: true, username: req.user.username }));

app.get('/api/zip/:zip', requireAuth, async (req, res) => {
  try {
    const details = await lookupZipDetails(req.params.zip);
    res.json(details);
  } catch (err) {
    res.status(400).json({ error: err.message || 'ZIP lookup failed' });
  }
});

app.get('/api/miles', requireAuth, async (req, res) => {
  try {
    const fromZip = await lookupZipDetails(req.query.pickup_zip);
    const toZip = await lookupZipDetails(req.query.delivery_zip);
    res.json({ miles: estimateRoadMiles(fromZip, toZip), pickup: fromZip, delivery: toZip });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Mileage lookup failed' });
  }
});

app.post('/quote', requireAuth, async (req, res) => {
  try {
    const { pickup, delivery, vehicles, trailer_type } = req.body || {};
    if (!pickup?.zip || !delivery?.zip) {
      return res.status(400).json({ error: 'Pickup ZIP and delivery ZIP are required.' });
    }
    if (!API_KEY) {
      return res.status(500).json({ error: 'Server misconfigured: SUPERDISPATCH_API_KEY is not set on the server.' });
    }

    const pickupZip = String(pickup.zip).trim();
    const dropZip = String(delivery.zip).trim();
    const pickupRuca = rucaData[pickupZip];
    const dropRuca = rucaData[dropZip];
    const pickupCategory = rucaCategory(pickupRuca);
    const dropoffCategory = rucaCategory(dropRuca);

    let estimatedMiles = null;
    try {
      const pickupDetails = await lookupZipDetails(pickupZip);
      const deliveryDetails = await lookupZipDetails(dropZip);
      estimatedMiles = estimateRoadMiles(pickupDetails, deliveryDetails);
    } catch (_) {}

    const sdResponse = await fetch(SUPERDISPATCH_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-KEY': API_KEY
      },
      body: JSON.stringify({ pickup, delivery, vehicles, trailer_type })
    });

    const rawText = await sdResponse.text();
    let sdJson;
    try {
      sdJson = JSON.parse(rawText);
    } catch {
      return res.status(502).json({
        error: 'Super Dispatch did not return valid JSON.',
        status: sdResponse.status,
        raw_response_preview: rawText.slice(0, 500)
      });
    }

    return res.status(sdResponse.status).json({
      superdispatch: sdJson,
      estimated_miles: estimatedMiles,
      pickup_access: {
        zip: pickupZip,
        ruca_code: pickupRuca ?? null,
        ruca_category: pickupCategory
      },
      dropoff_access: {
        zip: dropZip,
        ruca_code: dropRuca ?? null,
        ruca_category: dropoffCategory
      },
      lane_difficulty: calculateLaneDifficulty(pickupCategory, dropoffCategory)
    });
  } catch (err) {
    console.error('Quote route error:', err);
    res.status(500).json({ error: 'Server error', details: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
