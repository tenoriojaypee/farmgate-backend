// FarmGate delivery fee — barangay-level distance (Bulacan only).
// Distance = haversine(barangay centroid, barangay centroid) × ROAD_DISTANCE_FACTOR,
// rounded to 0.1 km. No municipality-center fallback for new orders.
// Client preview is NEVER trusted; the server recomputes in /delivery/quote,
// /accept (COD) and /create-payment (validateOrderForPayment, GCash).
"use strict";

const { BARANGAY_COORDS, CITIES } = require("./data/bulacanBarangays");

const DEFAULT_ROAD_FACTOR = 1.3;
const MIN_ROAD_FACTOR = 1;
const MAX_ROAD_FACTOR = 2;

// Inclusive upper bounds. 3.0 km => ₱25, 3.1 km => ₱35.
const FEE_TIERS = [
  { maxKm: 3.0, fee: 25, label: "0–3 km" },
  { maxKm: 6.0, fee: 35, label: "3.1–6 km" },
  { maxKm: 10.0, fee: 50, label: "6.1–10 km" },
  { maxKm: 15.0, fee: 65, label: "10.1–15 km" },
  { maxKm: 20.0, fee: 80, label: "15.1–20 km" },
  { maxKm: Infinity, fee: 100, label: "20.1 km+" },
];

const BULACAN = "bulacan";

class DeliveryFeeError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "DeliveryFeeError";
    this.code = code;
  }
}

const normalizeName = (value) =>
  String(value ?? "")
    .trim()
    .replace(/\s+/g, " ")
    .toLowerCase();

const normalizeCity = (value) =>
  normalizeName(value).replace(/^(city|municipality) of\s+/i, "");

const normalizeProvince = (value) => normalizeName(value);

function getRoadFactor(env = process.env) {
  const raw = env.FARMGATE_ROAD_DISTANCE_FACTOR;
  if (raw === undefined || raw === null || String(raw).trim() === "") {
    return DEFAULT_ROAD_FACTOR;
  }
  const num = Number(String(raw).trim());
  if (!Number.isFinite(num) || num < MIN_ROAD_FACTOR || num > MAX_ROAD_FACTOR) {
    return DEFAULT_ROAD_FACTOR;
  }
  return num;
}

function haversineKm(lat1, lng1, lat2, lng2) {
  const R = 6371;
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) *
      Math.cos(toRad(lat2)) *
      Math.sin(dLng / 2) *
      Math.sin(dLng / 2);
  return 2 * R * Math.asin(Math.sqrt(a));
}

function feeForDistance(distanceKm) {
  for (const tier of FEE_TIERS) {
    if (distanceKm <= tier.maxKm) {
      return { fee: tier.fee, tier: tier.label };
    }
  }
  const last = FEE_TIERS[FEE_TIERS.length - 1];
  return { fee: last.fee, tier: last.label };
}

function findCityDisplay(normalizedCity) {
  return CITIES.find((c) => normalizeCity(c) === normalizedCity) || null;
}

function lookupCoords(nCity, nBrgy) {
  return BARANGAY_COORDS[`${nCity}|${nBrgy}`] || null;
}

function cityHasAnyBarangay(nCity) {
  const prefix = `${nCity}|`;
  return Object.keys(BARANGAY_COORDS).some((k) => k.startsWith(prefix));
}

// farm, buyer: { province, city, barangay }
// dataOverride (tests only): { "ncity|nbrgy": { city, barangay, lat, lng } }
// Returns { distanceKm, fee, tier }. Throws DeliveryFeeError.
function quoteDeliveryFee(farm, buyer, opts = {}) {
  const data = opts.data || BARANGAY_COORDS;
  const roadFactor =
    opts.roadFactor !== undefined ? opts.roadFactor : getRoadFactor();

  const farmProvince = normalizeProvince(farm?.province);
  const buyerProvince = normalizeProvince(buyer?.province);

  if (farmProvince !== BULACAN) {
    throw new DeliveryFeeError(
      "INVALID_PROVINCE",
      `Farm province "${farm?.province || ""}" is outside the Bulacan-only delivery area.`
    );
  }
  if (buyerProvince !== BULACAN) {
    throw new DeliveryFeeError(
      "INVALID_PROVINCE",
      `Delivery address province "${buyer?.province || ""}" is outside the Bulacan-only delivery area.`
    );
  }

  const farmCity = normalizeCity(farm?.city);
  const buyerCity = normalizeCity(buyer?.city);
  const farmBrgy = normalizeName(farm?.barangay);
  const buyerBrgy = normalizeName(buyer?.barangay);

  if (!farmCity || !findCityDisplayIn(farmCity, opts)) {
    throw new DeliveryFeeError(
      "UNKNOWN_CITY",
      `Unknown farm city/municipality "${farm?.city || ""}". Pick a Bulacan city from the list.`
    );
  }
  if (!buyerCity || !findCityDisplayIn(buyerCity, opts)) {
    throw new DeliveryFeeError(
      "UNKNOWN_CITY",
      `Unknown delivery city/municipality "${buyer?.city || ""}". Pick a Bulacan city from the list.`
    );
  }
  if (!farmBrgy) {
    throw new DeliveryFeeError(
      "UNKNOWN_BARANGAY",
      `Farm barangay is missing. Ask the farmer to set their barangay in Farm Profile.`
    );
  }
  if (!buyerBrgy) {
    throw new DeliveryFeeError(
      "UNKNOWN_BARANGAY",
      `Delivery barangay is missing. Pick a barangay from the list.`
    );
  }

  // Same barangay (exact normalized city + barangay match) = 0 km, ₱25.
  // No coordinates needed — same place means no travel.
  if (farmCity === buyerCity && farmBrgy === buyerBrgy) {
    const base = feeForDistance(0);
    return { distanceKm: 0, fee: base.fee, tier: base.tier };
  }

  const farmHit = (data || {})[`${farmCity}|${farmBrgy}`] || null;
  const buyerHit = (data || {})[`${buyerCity}|${buyerBrgy}`] || null;

  if (!farmHit) {
    // Distinguish "barangay name does not exist in this city" from
    // "exists in CSV but has no trusted coords yet".
    if (!barangayExistsInCity(farmCity, farmBrgy, opts)) {
      throw new DeliveryFeeError(
        "UNKNOWN_BARANGAY",
        `Unknown farm barangay "${farm?.barangay || ""}" in ${farm?.city || ""}. Check the spelling and pick from the list (no guessing).`
      );
    }
    throw new DeliveryFeeError(
      "BARANGAY_NOT_SERVICEABLE",
      `Farm barangay "${farm?.barangay || ""}" in ${farm?.city || ""} has no verified coordinates yet, so delivery is blocked until it is field-verified.`
    );
  }
  if (!buyerHit) {
    if (!barangayExistsInCity(buyerCity, buyerBrgy, opts)) {
      throw new DeliveryFeeError(
        "UNKNOWN_BARANGAY",
        `Unknown barangay "${buyer?.barangay || ""}" in ${buyer?.city || ""}. Check the spelling and pick from the list (no guessing).`
      );
    }
    throw new DeliveryFeeError(
      "BARANGAY_NOT_SERVICEABLE",
      `Barangay "${buyer?.barangay || ""}" in ${buyer?.city || ""} has no verified coordinates yet, so delivery is blocked until it is field-verified.`
    );
  }

  if (
    !Number.isFinite(farmHit.lat) ||
    !Number.isFinite(farmHit.lng) ||
    !Number.isFinite(buyerHit.lat) ||
    !Number.isFinite(buyerHit.lng)
  ) {
    throw new DeliveryFeeError(
      "BARANGAY_NOT_SERVICEABLE",
      `Missing coordinates for the selected barangays, so delivery is blocked until they are field-verified.`
    );
  }

  const straight = haversineKm(farmHit.lat, farmHit.lng, buyerHit.lat, buyerHit.lng);
  const distanceKm = Math.round(straight * roadFactor * 10) / 10;
  const { fee, tier } = feeForDistance(distanceKm);
  return { distanceKm, fee, tier };

  function findCityDisplayIn(nCity, o) {
    if (o.data) {
      // Test-injected dataset: derive city list from keys
      if (Object.keys(o.data).some((k) => k.split("|")[0] === nCity)) return true;
    }
    if (o.cities) return o.cities.some((c) => normalizeCity(c) === nCity);
    return !!findCityDisplay(nCity) || cityHasAnyBarangay(nCity);
  }

  function barangayExistsInCity(nCity, nBrgy, o) {
    if (o.data) return !!o.data[`${nCity}|${nBrgy}`];
    // Production: check generated BARANGAYS_BY_CITY (includes rows without coords)
    try {
      const { BARANGAYS_BY_CITY } = require("./data/bulacanBarangays");
      const disp = findCityDisplay(nCity);
      const list = (disp && BARANGAYS_BY_CITY[disp]) || [];
      // Also try matching by normalized city across all display names
      if (list.length === 0) {
        for (const [d, arr] of Object.entries(BARANGAYS_BY_CITY)) {
          if (normalizeCity(d) === nCity) {
            return arr.some((r) => normalizeName(r.barangay) === nBrgy);
          }
        }
        return false;
      }
      return list.some((r) => normalizeName(r.barangay) === nBrgy);
    } catch {
      return !!lookupCoords(nCity, nBrgy);
    }
  }
}

module.exports = {
  quoteDeliveryFee,
  DeliveryFeeError,
  getRoadFactor,
  feeForDistance,
  haversineKm,
  normalizeName,
  normalizeCity,
  farmLocationFromProfile,
  buyerLocationFromAddress,
  computeDeliveryForOrder,
  FEE_TIERS,
  DEFAULT_ROAD_FACTOR,
};

// ---- Firestore-shape helpers (pure, no db access) ----

function farmLocationFromProfile(profile) {
  const p = profile || {};
  return {
    province: p.province || "",
    city: p.municipality || p.city || "",
    barangay: p.barangay || "",
  };
}

function buyerLocationFromAddress(address) {
  const a = address || {};
  return {
    province: a.province || "",
    city: a.city || a.municipality || "",
    barangay: a.barangay || "",
  };
}

// Decides the delivery money fields for an order WITHOUT trusting the client.
// - pickup => { deliveryFee: 0, distanceKm: 0, tier: null }
// - legacy order with no barangay (farm or buyer) => keep fee already written.
// - new order with missing/unknown barangay => throws DeliveryFeeError (blocked).
function computeDeliveryForOrder({ farmerProfile, order }, opts = {}) {
  const delivery = order?.delivery;
  if (delivery !== "delivery") {
    return { deliveryFee: 0, distanceKm: 0, tier: null, legacy: false };
  }
  const farm = farmLocationFromProfile(farmerProfile);
  const buyer = buyerLocationFromAddress(order?.address);

  const farmMissing =
    !String(farm.city || "").trim() || !String(farm.barangay || "").trim();
  const buyerMissing =
    !String(buyer.city || "").trim() || !String(buyer.barangay || "").trim();

  if (farmMissing || buyerMissing) {
    const stored = Number(order?.deliveryFee);
    if (Number.isFinite(stored) && stored >= 0) {
      // Legacy order written before barangays were required: do not recompute.
      return {
        deliveryFee: stored,
        distanceKm:
          Number.isFinite(Number(order?.distanceKm)) &&
          Number(order?.distanceKm) >= 0
            ? Number(order.distanceKm)
            : null,
        tier: order?.deliveryTier || order?.tier || "legacy",
        legacy: true,
      };
    }
    if (farmMissing) {
      throw new DeliveryFeeError(
        "UNKNOWN_BARANGAY",
        "This farm has no barangay set yet. Ask the farmer to pick their City and Barangay in Farm Profile before delivery."
      );
    }
    throw new DeliveryFeeError(
      "UNKNOWN_BARANGAY",
      "The delivery address has no barangay. Pick a Bulacan City and Barangay from the list."
    );
  }

  const q = quoteDeliveryFee(farm, buyer, opts);
  return { deliveryFee: q.fee, distanceKm: q.distanceKm, tier: q.tier, legacy: false };
}