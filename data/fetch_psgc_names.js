// One-off: builds bulacan_barangays.csv skeleton (city,barangay,lat,lng)
// from PSGC authoritative names. lat/lng left empty except verified entries.
// Run: node data/fetch_psgc_names.js
const fs = require("fs");
const path = require("path");

const CITY_CODE_TO_SHORT = {
  "031401000": "Angat",
  "031402000": "Balagtas",
  "031403000": "Baliwag",
  "031404000": "Bocaue",
  "031405000": "Bulakan",
  "031406000": "Bustos",
  "031407000": "Calumpit",
  "031408000": "Guiguinto",
  "031409000": "Hagonoy",
  "031410000": "Malolos",
  "031411000": "Marilao",
  "031412000": "Meycauayan",
  "031413000": "Norzagaray",
  "031414000": "Obando",
  "031415000": "Pandi",
  "031416000": "Paombong",
  "031417000": "Plaridel",
  "031418000": "Pulilan",
  "031419000": "San Ildefonso",
  "031420000": "San Jose del Monte",
  "031421000": "San Miguel",
  "031422000": "San Rafael",
  "031423000": "Santa Maria",
  "031424000": "Dona Remedios Trinidad",
};

// Verified barangay centroids (field-checked against PhilAtlas / city halls).
// Keys MUST match PSGC barangay names exactly (including " (Pob.)" and Ñ).
// DO NOT invent coordinates for other barangays — leave them empty so the
// validator flags them as MISSING instead of guessing.
const VERIFIED = {
  // key: city|barangay -> [lat, lng]
  "Malolos|Santo Niño (Pob.)": [14.8445, 120.8103],
  "Malolos|San Vicente (Pob.)": [14.8526, 120.8119],
  "Malolos|Bulihan": [14.8348, 120.8067],
  "Guiguinto|Poblacion": [14.8299, 120.8836],
  "Hagonoy|Santo Niño (Pob.)": [14.8339, 120.7341],
  "Hagonoy|San Agustin": [14.8412, 120.742],
  "Calumpit|Poblacion": [14.9172, 120.7669],
  "Meycauayan|Poblacion": [14.7333, 120.95],
  "Meycauayan|Ubihan": [14.7533, 120.9229], // OSM boundary relation 1710785 (bbox-verified village in Meycauayan); field-verify before production reliance
  "Baliwag|Poblacion": [14.9547, 120.8967],
  "San Jose del Monte|Poblacion": [14.8139, 121.0453],
};

async function main() {
  const citiesRes = await fetch(
    "https://psgc.gitlab.io/api/provinces/031400000/cities-municipalities"
  );
  const cities = await citiesRes.json();
  const codeToName = {};
  for (const c of cities) {
    codeToName[c.code] =
      CITY_CODE_TO_SHORT[c.code] || c.name.replace(/^City of /i, "").trim();
  }
  const brgyRes = await fetch(
    "https://psgc.gitlab.io/api/provinces/031400000/barangays"
  );
  const brgys = await brgyRes.json();
  const rows = [["city", "barangay", "lat", "lng"]];
  for (const b of brgys.sort((a, c) => {
    const ka = String(codeToName[a.municipalityCode || a.cityCode] || "");
    const kb = String(codeToName[c.municipalityCode || c.cityCode] || "");
    return ka.localeCompare(kb) || String(a.name).localeCompare(String(c.name));
  })) {
    const city =
      codeToName[b.municipalityCode || b.cityCode] ||
      b.municipalityCode ||
      b.cityCode;
    const barangay = String(b.name || "").trim();
    const key = city + "|" + barangay;
    const v = VERIFIED[key];
    rows.push([city, barangay, v ? String(v[0]) : "", v ? String(v[1]) : ""]);
  }
  const esc = (s) => (/[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s);
  const csv = rows.map((r) => r.map(esc).join(",")).join("\n") + "\n";
  const out = path.join(__dirname, "bulacan_barangays.csv");
  fs.writeFileSync(out, csv);
  console.log(`Wrote ${rows.length - 1} barangays to ${out}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});