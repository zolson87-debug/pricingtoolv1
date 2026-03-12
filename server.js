const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const SUPERDISPATCH_URL =
  process.env.SUPERDISPATCH_PRICING_URL ||
  "https://pricing-insights.superdispatch.com/api/v1/recommended-price";

const API_KEY = process.env.SUPERDISPATCH_API_KEY;
const APP_USERNAME = process.env.APP_USERNAME;
const APP_PASSWORD = process.env.APP_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET || "change-this-secret";

if (!API_KEY) console.warn("WARNING: SUPERDISPATCH_API_KEY is not set.");
if (!APP_USERNAME || !APP_PASSWORD) {
  console.warn("WARNING: APP_USERNAME or APP_PASSWORD is not set.");
}

let rucaData = {};
try {
  const rucaPath = path.join(__dirname, "ruca_by_zip.json");
  rucaData = JSON.parse(fs.readFileSync(rucaPath, "utf8"));
  console.log("RUCA data loaded:", Object.keys(rucaData).length, "ZIP codes");
} catch (err) {
  console.error("Failed to load RUCA file:", err);
}

function rucaCategory(code) {
  if (code === undefined || code === null || code === "") return "Unknown";
  const n = Number(code);
  if (n >= 1 && n <= 3) return "Metro";
  if (n >= 4 && n <= 6) return "Suburban / Small City";
  if (n >= 7 && n <= 9) return "Rural";
  if (n === 10) return "Very Remote";
  return "Unknown";
}

function laneDifficultyFromCategories(pickupCategory, dropoffCategory) {
  const p = String(pickupCategory || "").trim();
  const d = String(dropoffCategory || "").trim();
  if (!p || !d || p === "Unknown" || d === "Unknown") return "Unknown";
  if (p === "Very Remote" || d === "Very Remote") return "Very Hard";
  if (p === "Rural" || d === "Rural") return "Hard";
  if (
    (p === "Metro" && d === "Suburban / Small City") ||
    (p === "Suburban / Small City" && d === "Metro")
  ) return "Standard";
  if (p === "Metro" && d === "Metro") return "Easy";
  return "Standard";
}

function laneSurcharge(laneDifficulty) {
  if (laneDifficulty === "Hard") return 100;
  if (laneDifficulty === "Very Hard") return 150;
  return 0;
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const cookies = {};
  header.split(";").forEach((part) => {
    const [key, ...rest] = part.trim().split("=");
    if (!key) return;
    cookies[key] = decodeURIComponent(rest.join("="));
  });
  return cookies;
}

function signSession(username) {
  const payload = JSON.stringify({
    username,
    exp: Date.now() + 1000 * 60 * 60 * 12
  });
  const payloadBase64 = Buffer.from(payload).toString("base64url");
  const sig = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payloadBase64)
    .digest("base64url");
  return `${payloadBase64}.${sig}`;
}

function verifySession(token) {
  if (!token || !token.includes(".")) return null;
  const [payloadBase64, sig] = token.split(".");
  const expectedSig = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payloadBase64)
    .digest("base64url");
  if (sig !== expectedSig) return null;
  try {
    const payload = JSON.parse(Buffer.from(payloadBase64, "base64url").toString("utf8"));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const cookies = parseCookies(req);
  const session = verifySession(cookies.auth_session);
  if (!session) return res.redirect("/login");
  req.user = session;
  next();
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { response, text, json };
}

app.get("/login", (req, res) => {
  const cookies = parseCookies(req);
  const session = verifySession(cookies.auth_session);
  if (session) return res.redirect("/");
  res.sendFile(path.join(__dirname, "login.html"));
});

app.post("/login", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  if (!APP_USERNAME || !APP_PASSWORD) {
    return res.status(500).send("Server auth environment variables are not configured.");
  }
  if (username !== APP_USERNAME || password !== APP_PASSWORD) {
    return res.redirect("/login?error=1");
  }
  const token = signSession(username);
  const isProduction = process.env.NODE_ENV === "production";
  res.setHeader(
    "Set-Cookie",
    `auth_session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=43200${isProduction ? "; Secure" : ""}`
  );
  res.redirect("/");
});

app.post("/logout", (req, res) => {
  const isProduction = process.env.NODE_ENV === "production";
  res.setHeader(
    "Set-Cookie",
    `auth_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${isProduction ? "; Secure" : ""}`
  );
  res.redirect("/login");
});

app.get("/health", (req, res) => res.type("text/plain").send("OK"));
app.get("/", requireAuth, (req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/session", requireAuth, (req, res) => {
  res.json({ authenticated: true, username: req.user.username });
});

app.get("/api/zip/:zip", requireAuth, async (req, res) => {
  try {
    const zip = String(req.params.zip || "").trim();
    if (!/^\d{5}$/.test(zip)) {
      return res.status(400).json({ error: "ZIP must be 5 digits." });
    }
    const { response, json } = await fetchJson(`https://api.zippopotam.us/us/${zip}`);
    if (!response.ok || !json) {
      return res.status(404).json({ error: "ZIP not found." });
    }
    const place = json.places && json.places[0] ? json.places[0] : null;
    return res.json({
      zip,
      city: place ? place["place name"] || "" : "",
      state: place ? place["state abbreviation"] || "" : "",
      latitude: place ? Number(place.latitude) : null,
      longitude: place ? Number(place.longitude) : null
    });
  } catch (err) {
    return res.status(500).json({ error: "ZIP lookup failed.", details: err.message });
  }
});

app.get("/api/distance", requireAuth, async (req, res) => {
  try {
    const pickupZip = String(req.query.pickup_zip || "").trim();
    const deliveryZip = String(req.query.delivery_zip || "").trim();
    if (!/^\d{5}$/.test(pickupZip) || !/^\d{5}$/.test(deliveryZip)) {
      return res.status(400).json({ error: "pickup_zip and delivery_zip must be 5 digits." });
    }

    const [pickupData, deliveryData] = await Promise.all([
      fetchJson(`https://api.zippopotam.us/us/${pickupZip}`),
      fetchJson(`https://api.zippopotam.us/us/${deliveryZip}`)
    ]);

    if (!pickupData.response.ok || !pickupData.json || !deliveryData.response.ok || !deliveryData.json) {
      return res.status(404).json({ error: "Could not look up one or both ZIP codes." });
    }

    const p = pickupData.json.places && pickupData.json.places[0] ? pickupData.json.places[0] : null;
    const d = deliveryData.json.places && deliveryData.json.places[0] ? deliveryData.json.places[0] : null;
    const pLat = p ? Number(p.latitude) : null;
    const pLon = p ? Number(p.longitude) : null;
    const dLat = d ? Number(d.latitude) : null;
    const dLon = d ? Number(d.longitude) : null;

    if (![pLat, pLon, dLat, dLon].every(Number.isFinite)) {
      return res.status(502).json({ error: "ZIP coordinates were unavailable." });
    }

    const routeUrl = `https://router.project-osrm.org/route/v1/driving/${pLon},${pLat};${dLon},${dLat}?overview=false`;
    const routeData = await fetchJson(routeUrl);
    if (!routeData.response.ok || !routeData.json || !Array.isArray(routeData.json.routes) || !routeData.json.routes[0]) {
      return res.status(502).json({ error: "Distance service unavailable." });
    }

    const meters = Number(routeData.json.routes[0].distance || 0);
    const miles = meters / 1609.344;

    return res.json({
      pickup_zip: pickupZip,
      delivery_zip: deliveryZip,
      miles: Math.round(miles),
      miles_precise: Number(miles.toFixed(1))
    });
  } catch (err) {
    return res.status(500).json({ error: "Distance lookup failed.", details: err.message });
  }
});

app.post("/quote", requireAuth, async (req, res) => {
  try {
    const { pickup, delivery, vehicles, trailer_type } = req.body || {};
    if (!pickup?.zip || !delivery?.zip) {
      return res.status(400).json({ error: "Pickup ZIP and delivery ZIP are required." });
    }
    if (!API_KEY) {
      return res.status(500).json({ error: "Server misconfigured: SUPERDISPATCH_API_KEY is not set on the server." });
    }

    const pickupZip = String(pickup.zip).trim();
    const dropZip = String(delivery.zip).trim();
    const pickupRuca = rucaData[pickupZip];
    const dropRuca = rucaData[dropZip];
    const pickupCategory = rucaCategory(pickupRuca);
    const dropoffCategory = rucaCategory(dropRuca);
    const laneDifficulty = laneDifficultyFromCategories(pickupCategory, dropoffCategory);

    const sdResponse = await fetch(SUPERDISPATCH_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-KEY": API_KEY
      },
      body: JSON.stringify({ pickup, delivery, vehicles, trailer_type })
    });

    const rawText = await sdResponse.text();
    let sdJson;
    try {
      sdJson = JSON.parse(rawText);
    } catch {
      return res.status(502).json({
        error: "Super Dispatch did not return valid JSON.",
        status: sdResponse.status,
        raw_response_preview: rawText.slice(0, 500)
      });
    }

    let distanceInfo = null;
    try {
      const pZipInfo = await fetchJson(`https://api.zippopotam.us/us/${pickupZip}`);
      const dZipInfo = await fetchJson(`https://api.zippopotam.us/us/${dropZip}`);
      const p = pZipInfo.json?.places?.[0];
      const d = dZipInfo.json?.places?.[0];
      if (p && d) {
        const route = await fetchJson(`https://router.project-osrm.org/route/v1/driving/${p.longitude},${p.latitude};${d.longitude},${d.latitude}?overview=false`);
        const meters = Number(route.json?.routes?.[0]?.distance || 0);
        if (meters > 0) {
          const miles = meters / 1609.344;
          distanceInfo = { miles: Math.round(miles), miles_precise: Number(miles.toFixed(1)) };
        }
      }
    } catch (_) {
      distanceInfo = null;
    }

    return res.status(sdResponse.status).json({
      superdispatch: sdJson,
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
      lane: {
        difficulty: laneDifficulty,
        surcharge: laneSurcharge(laneDifficulty)
      },
      distance: distanceInfo
    });
  } catch (err) {
    console.error("Quote route error:", err);
    return res.status(500).json({ error: "Server error", details: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
