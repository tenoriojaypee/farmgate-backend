// Turns bulacan_barangays.csv (city,barangay,lat,lng) into a JS module.
// - (city, barangay) key must be unique (normalized: trim + lowercase + collapse spaces).
// - Flags MISSING (empty/non-numeric lat/lng) and SUSPICIOUS coordinates
//   (outside Bulacan bbox, 0/0, duplicates) and does NOT guess.
// - Writes bulacanBarangays.js with: BARANGAY_COORDS, CITIES, BARANGAYS_BY_CITY.
//
// Usage:
//   node data/build_barangay_data.js [--check-only]
//
// Exit code 1 on duplicate keys or malformed CSV. Missing coords are reported
// but do not fail the build (delivery is blocked at runtime for those rows).
const fs = require("fs");
const path = require("path");

const CSV_PATH = path.join(__dirname, "bulacan_barangays.csv");
const OUT_PATH = path.join(__dirname, "bulacanBarangays.js");

// Generous Bulacan bounding box (Luzon, Central Luzon). Anything outside is SUSPICIOUS.
const BBOX = { minLat: 14.4, maxLat: 15.4, minLng: 120.5, maxLng: 121.4 };

const normalize = (s) =>
  String(s || "")
    .trim()
    .replace(/\s+/g, " ")
    .toLowerCase();

function parseCsv(text) {
  // Minimal CSV parser supporting quoted fields with commas/quotes.
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (c === "\r") {
      // skip, handled by \n
    } else {
      field += c;
    }
  }
  if (field !== "" || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((r) => r.some((f) => String(f).trim() !== ""));
}

function main() {
  const checkOnly = process.argv.includes("--check-only");
  const raw = fs.readFileSync(CSV_PATH, "utf8");
  const rows = parseCsv(raw);
  if (rows.length < 2) {
    console.error("CSV is empty or missing header.");
    process.exit(1);
  }
  const header = rows[0].map((h) => h.trim().toLowerCase());
  const ci = header.indexOf("city");
  const bi = header.indexOf("barangay");
  const la = header.indexOf("lat");
  const ln = header.indexOf("lng");
  if (ci < 0 || bi < 0 || la < 0 || ln < 0) {
    console.error("CSV header must be: city,barangay,lat,lng");
    process.exit(1);
  }

  const seen = new Map(); // normalized key -> line number
  const coords = {}; // "city|barangay" normalized -> { city, barangay, lat, lng }
  const citiesSet = new Map(); // normalized city -> display name
  const byCity = new Map(); // normalized city -> [{ barangay, lat, lng, hasCoords }]

  const missing = [];
  const suspicious = [];
  const duplicates = [];
  const coordSeen = new Map(); // "lat,lng" -> first key (detect copy-paste dupes)

  for (let i = 1; i < rows.length; i++) {
    const line = i + 1;
    const cityDisp = String(rows[i][ci] || "").trim().replace(/\s+/g, " ");
    const brgyDisp = String(rows[i][bi] || "").trim().replace(/\s+/g, " ");
    const latRaw = String(rows[i][la] || "").trim();
    const lngRaw = String(rows[i][ln] || "").trim();

    if (!cityDisp || !brgyDisp) {
      console.error(`Line ${line}: empty city or barangay.`);
      process.exit(1);
    }
    const nCity = normalize(cityDisp);
    const nBrgy = normalize(brgyDisp);
    const key = `${nCity}|${nBrgy}`;

    if (seen.has(key)) {
      duplicates.push(
        `Line ${line}: duplicate (city,barangay) key "${cityDisp} | ${brgyDisp}" (first at line ${seen.get(key)})`
      );
      continue;
    }
    seen.set(key, line);

    if (!citiesSet.has(nCity)) citiesSet.set(nCity, cityDisp);
    if (!byCity.has(nCity)) byCity.set(nCity, []);

    const lat = latRaw === "" ? NaN : Number(latRaw);
    const lng = lngRaw === "" ? NaN : Number(lngRaw);

    if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
      missing.push(`${cityDisp} | ${brgyDisp} (line ${line})`);
      byCity.get(nCity).push({ barangay: brgyDisp, lat: null, lng: null, hasCoords: false });
      continue;
    }

    const reasons = [];
    if (lat === 0 && lng === 0) reasons.push("0,0 null island");
    if (lat < BBOX.minLat || lat > BBOX.maxLat || lng < BBOX.minLng || lng > BBOX.maxLng)
      reasons.push(`outside Bulacan bbox (${lat},${lng})`);
    const cl = `${lat},${lng}`;
    if (coordSeen.has(cl)) reasons.push(`duplicate coords with ${coordSeen.get(cl)}`);
    else coordSeen.set(cl, `${cityDisp} | ${brgyDisp}`);

    if (reasons.length > 0) {
      suspicious.push(`${cityDisp} | ${brgyDisp} (${lat},${lng}) — ${reasons.join("; ")} (line ${line})`);
      // Suspicious rows are NOT trusted: excluded from coords, kept in list as unserviceable.
      byCity.get(nCity).push({ barangay: brgyDisp, lat, lng, hasCoords: false, suspicious: true });
      continue;
    }

    coords[key] = { city: cityDisp, barangay: brgyDisp, lat, lng };
    byCity.get(nCity).push({ barangay: brgyDisp, lat, lng, hasCoords: true });
  }

  // Sort cities and barangays for stable output
  const cities = Array.from(citiesSet.values()).sort((a, b) => a.localeCompare(b));
  const barangaysByCity = {};
  for (const [nCity, list] of byCity.entries()) {
    const disp = citiesSet.get(nCity);
    list.sort((a, b) => a.barangay.localeCompare(b.barangay));
    barangaysByCity[disp] = list;
  }

  console.log(`Parsed ${seen.size} rows from bulacan_barangays.csv`);
  console.log(`  with coords: ${Object.keys(coords).length}`);
  console.log(`  missing coords: ${missing.length}`);
  console.log(`  suspicious: ${suspicious.length}`);
  console.log(`  duplicate keys: ${duplicates.length}`);

  if (duplicates.length > 0) {
    console.error("\nDUPLICATE (city,barangay) KEYS — fix CSV, keys must be unique:");
    for (const d of duplicates) console.error("  " + d);
    process.exit(1);
  }
  if (missing.length > 0) {
    console.log("\nMISSING coordinates (delivery BLOCKED for these until field-verified — not guessed):");
    for (const m of missing.slice(0, 50)) console.log("  " + m);
    if (missing.length > 50) console.log(`  ... and ${missing.length - 50} more`);
  }
  if (suspicious.length > 0) {
    console.log("\nSUSPICIOUS coordinates (excluded from routing — verify in the field):");
    for (const s of suspicious) console.log("  " + s);
  }

  if (checkOnly) return;

  const out =
    `// AUTO-GENERATED by data/build_barangay_data.js — do not edit by hand.\n` +
    `// Source: data/bulacan_barangays.csv (${seen.size} rows, ${Object.keys(coords).length} with trusted coords).\n` +
    `// Rows with missing/suspicious coords are listed in BARANGAYS_BY_CITY with hasCoords:false\n` +
    `// and BLOCK delivery at runtime (no guessing, no municipality fallback).\n` +
    `"use strict";\n\n` +
    `const BARANGAY_COORDS = ${JSON.stringify(coords, null, 2)};\n\n` +
    `const CITIES = ${JSON.stringify(cities, null, 2)};\n\n` +
    `const BARANGAYS_BY_CITY = ${JSON.stringify(barangaysByCity, null, 2)};\n\n` +
    `module.exports = { BARANGAY_COORDS, CITIES, BARANGAYS_BY_CITY };\n`;

  fs.writeFileSync(OUT_PATH, out);
  console.log(`\nWrote ${OUT_PATH}`);
}

main();