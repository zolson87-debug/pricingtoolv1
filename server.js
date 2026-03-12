const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

const SUPERDISPATCH_URL =
  process.env.SUPERDISPATCH_PRICING_URL ||
  "https://pricing-insights.superdispatch.com/api/v1/recommended-price";

const API_KEY = process.env.SUPERDISPATCH_API_KEY;
const APP_USERNAME = process.env.APP_USERNAME;
const APP_PASSWORD = process.env.APP_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET || "change-this-secret";

if (!API_KEY) {
  console.warn("WARNING: SUPERDISPATCH_API_KEY is not set.");
}
if (!APP_USERNAME || !APP_PASSWORD) {
  console.warn("WARNING: APP_USERNAME or APP_PASSWORD is not set.");
}

let rucaData = {};
try {
  const rucaPath = path.join(__dirname, "ruca_by_zip.json");
  const raw = fs.readFileSync(rucaPath, "utf8");
  rucaData = JSON.parse(raw);
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
  if (p === "Metro" && d === "Metro") return "Easy";
  return "Standard";
}

function laneDifficultySurcharge(laneDifficulty) {
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

  if (!session) {
    return res.redirect("/login");
  }

  req.user = session;
  next();
}

async function lookupZipDetails(zip) {
  const cleanZip = String(zip || "").trim();
  if (!/^\d{5}$/.test(cleanZip)) {
    return { zip: cleanZip, city: "", state: "", found: false };
  }

  try {
    const response = await fetch(`https://api.zippopotam.us/us/${cleanZip}`);
    if (!response.ok) {
      return { zip: cleanZip, city: "", state: "", found: false };
    }

    const data = await response.json();
    const place = data?.places?.[0] || null;

    return {
      zip: cleanZip,
      city: place?.["place name"] || "",
      state: place?.["state abbreviation"] || "",
      found: !!place
    };
  } catch {
    return { zip: cleanZip, city: "", state: "", found: false };
  }
}

app.get("/login", (req, res) => {
  const cookies = parseCookies(req);
  const session = verifySession(cookies.auth_session);

  if (session) {
    return res.redirect("/");
  }

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

app.get("/health", (req, res) => {
  res.type("text/plain").send("OK");
});

app.get("/", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/session", requireAuth, (req, res) => {
  res.json({
    authenticated: true,
    username: req.user.username
  });
});

app.get("/zip/:zip", requireAuth, async (req, res) => {
  const result = await lookupZipDetails(req.params.zip);
  if (!result.found) {
    return res.status(404).json({ error: "ZIP not found.", zip: result.zip });
  }
  res.json(result);
});

app.post("/quote", requireAuth, async (req, res) => {
  try {
    const { pickup, delivery, vehicles, trailer_type } = req.body || {};

    if (!pickup?.zip || !delivery?.zip) {
      return res.status(400).json({ error: "Pickup ZIP and delivery ZIP are required." });
    }

    if (!Array.isArray(vehicles) || vehicles.length === 0) {
      return res.status(400).json({ error: "At least one vehicle is required." });
    }

    if (!API_KEY) {
      return res.status(500).json({
        error: "Server misconfigured: SUPERDISPATCH_API_KEY is not set on the server."
      });
    }

    const pickupZip = String(pickup.zip).trim();
    const dropZip = String(delivery.zip).trim();

    const pickupRuca = rucaData[pickupZip];
    const dropRuca = rucaData[dropZip];
    const pickupCategory = rucaCategory(pickupRuca);
    const dropoffCategory = rucaCategory(dropRuca);
    const laneDifficulty = laneDifficultyFromCategories(pickupCategory, dropoffCategory);

    const payload = {
      pickup,
      delivery,
      vehicles: vehicles.map((vehicle) => {
        const normalized = {
          type: String(vehicle?.type || "sedan"),
          is_inoperable: !!vehicle?.is_inoperable,
          make: String(vehicle?.make || ""),
          model: String(vehicle?.model || "")
        };

        if (vehicle?.year !== undefined && vehicle?.year !== null && String(vehicle.year).trim() !== "") {
          normalized.year = Number(vehicle.year);
        }

        return normalized;
      }),
      trailer_type: trailer_type || "open"
    };

    const sdResponse = await fetch(SUPERDISPATCH_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-KEY": API_KEY
      },
      body: JSON.stringify(payload)
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

    const sdPrice = Number(sdJson?.data?.price);
    const sdPricePerMile = Number(sdJson?.data?.price_per_mile);
    const sdConfidence = sdJson?.data?.confidence ?? null;

    return res.status(sdResponse.status).json({
      superdispatch: sdJson,
      pricing_reference: {
        sd_price: Number.isFinite(sdPrice) ? sdPrice : null,
        sd_price_per_mile: Number.isFinite(sdPricePerMile) ? sdPricePerMile : null,
        sd_confidence: sdConfidence
      },
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
      lane_difficulty: {
        value: laneDifficulty,
        surcharge: laneDifficultySurcharge(laneDifficulty)
      }
    });
  } catch (err) {
    console.error("Quote route error:", err);
    return res.status(500).json({ error: "Server error", details: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
