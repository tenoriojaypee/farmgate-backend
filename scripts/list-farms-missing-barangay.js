// Lists farmer profiles that still need a City + Barangay re-pick.
// Delivery stays BLOCKED for these farms until they save a barangay in
// Farm Profile. Old orders keep the fee already written (no recompute).
//
// Usage:
//   node scripts/list-farms-missing-barangay.js
//
// Requires the same Firebase Admin env as index.js:
//   FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY
"use strict";
require("dotenv").config();
const { initializeApp, getApps, cert } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");

async function main() {
  const projectId = (process.env.FIREBASE_PROJECT_ID || "").trim();
  const clientEmail = (process.env.FIREBASE_CLIENT_EMAIL || "").trim();
  const privateKey = (process.env.FIREBASE_PRIVATE_KEY || "")
    .replace(/\\n/g, "\n")
    .trim();
  if (!projectId || !clientEmail || !privateKey) {
    console.error("Firebase Admin credentials are incomplete.");
    process.exit(1);
  }
  const app =
    getApps().length > 0
      ? getApps()[0]
      : initializeApp({ credential: cert({ projectId, clientEmail, privateKey }) });
  const db = getFirestore(app);
  const snap = await db.collection("users").where("role", "==", "farmer").get();
  const missing = [];
  for (const doc of snap.docs) {
    const u = doc.data() || {};
    const city = String(u.municipality || u.city || "").trim();
    const brgy = String(u.barangay || "").trim();
    if (!city || !brgy) {
      missing.push({
        farmerId: doc.id,
        farmName: u.farmName || "(no farm name)",
        email: u.email || "",
        city: city || "(missing)",
        barangay: brgy || "(missing)",
      });
    }
  }
  console.log(`Farmers checked: ${snap.size}`);
  console.log(`Missing City/Barangay: ${missing.length}`);
  for (const m of missing) {
    console.log(`- ${m.farmerId} | ${m.farmName} | ${m.email} | ${m.city} | ${m.barangay}`);
  }
  if (missing.length > 0) {
    console.log(
      "\nMigration: ask each farmer to open Farm Profile, pick City then Barangay (province locked to Bulacan), and save. Delivery stays blocked for that farm until they do. Old orders are untouched."
    );
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});