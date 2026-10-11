const express = require("express");
const crypto = require("crypto");
const { FieldValue } = require("firebase-admin/firestore");
const {
  computeDeliveryForOrder,
  DeliveryFeeError,
} = require("./deliveryFee");

/* =========================================================
   CONSTANTS
========================================================= */

const XENDIT_BASE_URL = "https://api.xendit.co";
const XENDIT_PAYMENT_API_VERSION = "2024-11-11";
const XENDIT_PAYOUT_API_VERSION = "2025-09-01";
const XENDIT_TIMEOUT_MS = 20000;

const DEFAULT_COMMISSION_RATE = 0.03;
const DEFAULT_MIN_COMMISSION_DEPOSIT = 100;
const MAX_COMMISSION_DEPOSIT = 100000;
const DEFAULT_MIN_WITHDRAWAL = 1;
const DEFAULT_DELIVERY_FEE = 35;
const TRANSACTION_LIMIT = 50;

/*
  MONEY MODEL (single source of truth)

  availableBalance : GCash earnings credited at delivery.
                     INCLUDES any amount currently held for withdrawals.
  reservedBalance  : amount of availableBalance held for in-flight withdrawals.
  withdrawable     : availableBalance - reservedBalance

  Withdrawal lifecycle:
    request  -> reserved += amount                         (available unchanged)
    success  -> reserved -= amount, available -= amount
    failure  -> reserved -= amount                         (available unchanged)
    reversal after success -> available += amount

  commissionReserveBalance : free COD commission deposit
  commissionReserveHeld    : COD commission held for accepted COD orders

  pendingBalance is NOT stored. It is computed from orders on demand.
*/

/* =========================================================
   HELPERS
========================================================= */

// Safe: invalid / missing values become 0. Use for stored balances.
const roundMoney = (value) => {
  const number = Number(value);
  if (!Number.isFinite(number)) return 0;
  return Math.round((number + Number.EPSILON) * 100) / 100;
};

// Strict: invalid input becomes NaN. Use to validate user input.
const normalizeAmount = (value) => {
  if (value === null || value === undefined || value === "") return NaN;
  const number = Number(value);
  if (!Number.isFinite(number)) return NaN;
  return roundMoney(number);
};

const getEnv = (name) => {
  const value = process.env[name];
  return typeof value === "string" && value.trim() !== ""
    ? value.trim()
    : undefined;
};

const getCommissionRate = () => {
  const configured = Number(
    getEnv("FARMGATE_COMMISSION_RATE") || DEFAULT_COMMISSION_RATE
  );

  return Number.isFinite(configured) && configured >= 0
    ? configured
    : DEFAULT_COMMISSION_RATE;
};

const getMinimumCommissionDeposit = () => {
  const value = normalizeAmount(
    getEnv("FARMER_COMMISSION_DEPOSIT_MINIMUM") ||
      DEFAULT_MIN_COMMISSION_DEPOSIT
  );
  return Number.isFinite(value) && value > 0
    ? value
    : DEFAULT_MIN_COMMISSION_DEPOSIT;
};

const getMinimumWithdrawal = () => {
  const value = normalizeAmount(
    getEnv("FARMER_MIN_WITHDRAWAL") || DEFAULT_MIN_WITHDRAWAL
  );
  return Number.isFinite(value) && value > 0 ? value : DEFAULT_MIN_WITHDRAWAL;
};

const getDeliveryFee = () => {
  const value = normalizeAmount(
    getEnv("FARMGATE_DELIVERY_FEE") || DEFAULT_DELIVERY_FEE
  );
  return Number.isFinite(value) && value >= 0 ? value : DEFAULT_DELIVERY_FEE;
};

const createIdempotencyKey = (prefix) =>
  `${prefix}-${Date.now()}-${crypto.randomUUID()}`;

const httpError = (status, message, extra = {}) =>
  Object.assign(new Error(message), { status, ...extra });

const safeCompare = (first, second) => {
  if (typeof first !== "string" || typeof second !== "string") return false;
  const a = Buffer.from(first, "utf8");
  const b = Buffer.from(second, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

const normalizeGcashNumber = (value) => {
  const digits = String(value || "").trim().replace(/\D/g, "");

  if (/^09\d{9}$/.test(digits)) return digits;
  if (/^639\d{9}$/.test(digits)) return `0${digits.slice(2)}`;

  throw new Error("Invalid GCash number. Use 09XXXXXXXXX.");
};

const maskGcashNumber = (number) => {
  const normalized = normalizeGcashNumber(number);
  return `${normalized.slice(0, 4)}****${normalized.slice(-3)}`;
};

const splitName = (fullName) => {
  const parts = String(fullName || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean);

  if (parts.length === 0) return { givenName: "Farmer", surname: "Account" };
  if (parts.length === 1) return { givenName: parts[0], surname: "Farmer" };

  return {
    givenName: parts.slice(0, -1).join(" "),
    surname: parts[parts.length - 1],
  };
};

const toMillis = (value) => {
  if (!value) return 0;
  if (typeof value.toMillis === "function") return value.toMillis();
  if (typeof value.seconds === "number") return value.seconds * 1000;
  if (typeof value === "number") return value;
  const parsed = new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed : 0;
};

/* =========================================================
   XENDIT (payments)
========================================================= */

const xenditRequest = async (path, options = {}) => {
  const secretKey = getEnv("XENDIT_SECRET_KEY");
  if (!secretKey) throw new Error("XENDIT_SECRET_KEY is not configured.");

  const response = await fetch(`${XENDIT_BASE_URL}${path}`, {
    ...options,
    signal: AbortSignal.timeout(XENDIT_TIMEOUT_MS),
    headers: {
      Authorization: `Basic ${Buffer.from(`${secretKey}:`).toString("base64")}`,
      "Content-Type": "application/json",
      "api-version": XENDIT_PAYMENT_API_VERSION,
      ...(options.headers || {}),
    },
  });

  const text = await response.text();
  let data = {};

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }

  if (!response.ok) {
    const error = new Error(
      data?.message ||
        data?.error_code ||
        `Xendit request failed with status ${response.status}.`
    );
    error.status = response.status;
    error.response = data;
    throw error;
  }

  return data;
};

const getRedirectUrl = (actions) => {
  if (!Array.isArray(actions)) return null;

  const action = actions.find((item) => item?.type === "REDIRECT_CUSTOMER");

  return action?.value || action?.url || null;
};

/* =========================================================
   AUTH
========================================================= */

const getAuthUser = async (req, auth) => {
  const authorization = req.headers.authorization;

  if (
    typeof authorization !== "string" ||
    !authorization.startsWith("Bearer ")
  ) {
    throw httpError(401, "Missing Firebase authentication token.");
  }

  try {
    return await auth.verifyIdToken(authorization.substring("Bearer ".length));
  } catch {
    throw httpError(401, "Invalid or expired login session.");
  }
};

const requireFarmer = async (req, auth, db) => {
  const decoded = await getAuthUser(req, auth);
  const userSnap = await db.collection("users").doc(decoded.uid).get();

  if (!userSnap.exists) {
    throw httpError(404, "User profile not found.");
  }

  const user = userSnap.data() || {};

  if (user.role !== "farmer") {
    throw httpError(403, "Only farmer accounts can access this wallet.");
  }

  return { decoded, user };
};

// Auth problems -> 401/403/404. Everything else -> fallback (usually 500,
// so a Firestore/Xendit failure is never misreported as "session expired").
const sendWalletError = (res, error, fallbackStatus = 500) => {
  const status =
    Number.isFinite(Number(error?.status)) && Number(error.status) >= 400
      ? Number(error.status)
      : fallbackStatus;

  return res.status(status).json({ success: false, error: error.message });
};

// Never throws: a corrupt/legacy payout doc must not break the whole wallet.
const safeMaskGcashNumber = (storedMasked, storedNumber) => {
  if (typeof storedMasked === "string" && storedMasked.trim() !== "") {
    return storedMasked;
  }

  try {
    return maskGcashNumber(storedNumber || "");
  } catch {
    return "";
  }
};

/* =========================================================
   ADMIN WALLET (single shared wallet for the platform)
   Farmer wallets and the admin wallet live behind the same
   /wallet router. Admin ledger entries reuse the
   walletTransactions collection with farmerId === ADMIN_LEDGER_ID
   so history queries stay uniform.
========================================================= */

const ADMIN_WALLET_ID = "main";
const ADMIN_LEDGER_ID = "admin-main";

const requireAdmin = async (req, auth, db) => {
  const decoded = await getAuthUser(req, auth);

  const adminSnap = await db.collection("admins").doc(decoded.uid).get();

  if (adminSnap.exists && (adminSnap.data() || {}).status === "Active") {
    return { decoded };
  }

  const userSnap = await db.collection("users").doc(decoded.uid).get();

  if (userSnap.exists && (userSnap.data() || {}).role === "admin") {
    return { decoded };
  }

  throw httpError(403, "Only admin accounts can access this wallet.");
};

const sanitizeAdminWallet = (data = {}) => ({
  availableBalance: roundMoney(data.availableBalance),
  totalCommissionEarned: roundMoney(data.totalCommissionEarned),
  totalWithdrawn: roundMoney(data.totalWithdrawn),
  pendingWithdrawal: roundMoney(data.pendingWithdrawal),
  updatedAt: data.updatedAt || null,
});

const getAdminWithdrawableAmount = (wallet) =>
  Math.max(
    0,
    roundMoney(
      roundMoney(wallet.availableBalance) -
        roundMoney(wallet.pendingWithdrawal)
    )
  );

/* Same Xendit payout call as farmers. The UI only collects name + number
   (like the farmer wallet), so the address falls back to the stored payout
   account, then the admin profile — same pattern as farmer profiles. */
const adminPayoutRequest = async ({
  idempotencyKey,
  referenceId,
  payoutAccount,
  profile = {},
  amount,
}) => {
  const accountName = String(payoutAccount.accountName || "").trim();
  const postalCode = String(
    payoutAccount.postalCode ||
      profile.postalCode ||
      profile.postal_code ||
      profile.zipCode ||
      profile.zip ||
      ""
  ).trim();
  const payoutCity = String(
    payoutAccount.city || profile.municipality || profile.city || ""
  ).trim();
  const payoutProvince = String(
    payoutAccount.province || profile.province || ""
  ).trim();
  const payoutStreet = String(
    payoutAccount.street ||
      profile.street ||
      profile.address ||
      profile.addressLine ||
      profile.location ||
      profile.barangay ||
      ""
  ).trim();

  // Address is optional in the app (name + number only, like the farmer
  // wallet). Send whatever is on file and let Xendit validate — its error
  // details are surfaced to the UI.
  const adminAddress = { country: "PH" };
  if (payoutProvince) adminAddress.province_state = payoutProvince;
  if (payoutCity) adminAddress.city = payoutCity;
  if (payoutStreet) adminAddress.street_line_1 = payoutStreet;
  if (/^\d{4}$/.test(postalCode)) adminAddress.postal_code = postalCode;

  return payoutRequest({
    idempotencyKey,
    referenceId,
    accountName,
    accountNumber: payoutAccount.accountNumber,
    amount,
    user: {
      farmerId: ADMIN_LEDGER_ID,
      payoutPostalCode: "",
      municipality: "",
      province: "",
      street: "",
    },
    addressOverride: adminAddress,
  });
};

/* =========================================================
   WALLET SHAPE
========================================================= */

const walletDefaults = (farmerId) => ({
  farmerId,
  availableBalance: 0,
  pendingBalance: 0,
  reservedBalance: 0,

  commissionReserveBalance: 0,
  commissionReserveHeld: 0,
  totalCommissionDeposited: 0,
  totalCodCommissionPaid: 0,

  codCommissionDue: 0,
  codDeliveryFeeDue: 0,

  totalEarned: 0,
  totalWithdrawn: 0,
  totalGcashEarnings: 0,

  minimumReserve: 0,
  currency: "PHP",
});

const sanitizeWallet = (farmerId, data = {}) => ({
  ...walletDefaults(farmerId),
  ...data,
  farmerId,

  availableBalance: roundMoney(data.availableBalance),
  // Pending earnings are computed from orders, never stored.
  pendingBalance: 0,
  reservedBalance: roundMoney(data.reservedBalance),

  commissionReserveBalance: roundMoney(data.commissionReserveBalance),
  commissionReserveHeld: roundMoney(data.commissionReserveHeld),
  totalCommissionDeposited: roundMoney(data.totalCommissionDeposited),
  totalCodCommissionPaid: roundMoney(data.totalCodCommissionPaid),

  codCommissionDue: roundMoney(data.codCommissionDue),
  codDeliveryFeeDue: roundMoney(data.codDeliveryFeeDue),

  totalEarned: roundMoney(data.totalEarned),
  totalWithdrawn: roundMoney(data.totalWithdrawn),
  totalGcashEarnings: roundMoney(data.totalGcashEarnings),

  minimumReserve: 0,
  currency: "PHP",
});

const getWithdrawableAmount = (wallet) =>
  Math.max(
    0,
    roundMoney(
      roundMoney(wallet.availableBalance) - roundMoney(wallet.reservedBalance)
    )
  );

/* =========================================================
   ORDER MONEY HELPERS
========================================================= */

const getOrderSubtotal = (order) => {
  const savedSubtotal = normalizeAmount(order?.subTotal);

  if (Number.isFinite(savedSubtotal) && savedSubtotal >= 0) {
    return savedSubtotal;
  }

  return roundMoney(
    (Array.isArray(order?.products) ? order.products : []).reduce(
      (sum, item) =>
        sum + Number(item?.price || 0) * Number(item?.quantity || 0),
      0
    )
  );
};

const getCommissionForSubtotal = (subtotal) => {
  const rate = getCommissionRate();
  return {
    rate,
    subtotal: roundMoney(subtotal),
    amount: roundMoney(roundMoney(subtotal) * rate),
  };
};

const getCodCommission = (order) =>
  getCommissionForSubtotal(getOrderSubtotal(order));

const getExpectedFarmerEarning = (order) => {
  const commission = getCommissionForSubtotal(getOrderSubtotal(order));
  return roundMoney(Math.max(0, commission.subtotal - commission.amount));
};

/*
  Re-prices an order from the products collection (never trusts the client).
  Delivery fee is recomputed from barangay centroids:
  farm barangay from users/{farmerId}, buyer barangay from order.address.
  Legacy orders with no barangay keep the fee already written.
  MUST be called inside a transaction BEFORE any transaction write.
*/
const priceOrderOnServer = async (transaction, db, order) => {
  const items = Array.isArray(order.products) ? order.products : [];

  if (items.length === 0) {
    throw new Error("Order contains no products.");
  }

  const seen = new Set();

  const refs = items.map((item) => {
    const productId = String(item?.productId || "").trim();

    if (!productId) throw new Error("Order contains an invalid productId.");

    if (seen.has(productId)) {
      throw new Error(`Duplicate product in order: ${productId}`);
    }

    seen.add(productId);

    return db.collection("products").doc(productId);
  });

  const snaps = await Promise.all(refs.map((ref) => transaction.get(ref)));

  let subtotal = 0;

  const products = items.map((item, index) => {
    const snap = snaps[index];

    if (!snap.exists) {
      throw new Error(`Product ${item.productId} not found.`);
    }

    const product = snap.data() || {};

    if (product.farmerId !== order.farmerId) {
      throw new Error(
        `Product ${item.productId} does not belong to this farmer.`
      );
    }

    if (product.archived === true) {
      throw new Error(`Product ${product.name || item.productId} is archived.`);
    }

    const price = Number(product.price);
    const quantity = Number(item.quantity);

    if (!Number.isFinite(price) || price < 0) {
      throw new Error(`Invalid price for ${product.name || item.productId}.`);
    }

    if (!Number.isFinite(quantity) || quantity <= 0) {
      throw new Error(`Invalid quantity for ${product.name || item.productId}.`);
    }

    subtotal += roundMoney(price * quantity);

    return {
      ...item,
      price,
      quantity,
      name: product.name || item.name || "",
      unit: product.unit || item.unit || "",
    };
  });

  subtotal = roundMoney(subtotal);

  // Barangay-level delivery fee. Reads the farm profile inside the same
  // transaction (read-before-write) and NEVER uses client-sent fee/distance.
  // Throws DeliveryFeeError when the address can't be delivered to — the
  // caller must keep the order pending and return a clear error.
  let deliveryFee = 0;
  let distanceKm = 0;
  let deliveryTier = null;
  let deliveryLegacy = false;

  if (order.delivery === "delivery") {
    const farmerRef = db.collection("users").doc(String(order.farmerId));
    const farmerSnap = await transaction.get(farmerRef);
    const farmerProfile = farmerSnap.exists ? farmerSnap.data() : {};
    const computed = computeDeliveryForOrder({ farmerProfile, order });
    deliveryFee = computed.deliveryFee;
    distanceKm = computed.distanceKm;
    deliveryTier = computed.tier;
    deliveryLegacy = computed.legacy === true;
  }

  return {
    products,
    subtotal,
    deliveryFee,
    distanceKm,
    deliveryTier,
    deliveryLegacy,
    total: roundMoney(subtotal + deliveryFee),
  };
};

const PENDING_ORDER_STATUSES = ["accepted", "processing", "to_receive"];

const isIndexMissingError = (error) => {
  if (!error) return false;
  if (error?.code === 9 || error?.code === "failed-precondition") return true;
  const msg = String(error?.message || "").toLowerCase();
  return msg.includes("composite index") || msg.includes("requires an index");
};

const sumPendingFromDocs = (docs) => {
  const pendingStatuses = new Set(PENDING_ORDER_STATUSES);
  let total = 0;

  for (const docSnap of docs) {
    const order = docSnap.data() || {};

    if (!pendingStatuses.has(String(order.status || ""))) continue;

    // Pending Product Earnings are GCash only. COD buyers pay the farmer directly.
    if (order.payment !== "gcash") continue;
    if (order.paymentStatus !== "paid") continue;

    // Already delivered / credited to the wallet.
    if (order.financialStatus === "settled") continue;
    if (order.farmerWalletCredited === true) continue;
    if (order.deliveredAt) continue;

    total += getExpectedFarmerEarning(order);
  }

  return roundMoney(total);
};

const getPendingProductBalance = async (db, farmerId) => {
  // Fast path: only pending statuses, only the fields needed for pricing.
  // Needs composite index: farmerId ASC + status ASC. Falls back below.
  try {
    const snapshot = await db
      .collection("orders")
      .where("farmerId", "==", farmerId)
      .where("status", "in", PENDING_ORDER_STATUSES)
      .select(
        "status",
        "payment",
        "paymentStatus",
        "financialStatus",
        "farmerWalletCredited",
        "deliveredAt",
        "subTotal",
        "products"
      )
      .get();

    return sumPendingFromDocs(snapshot.docs);
  } catch (error) {
    if (!isIndexMissingError(error)) throw error;

    console.warn(
      "orders needs a composite index (farmerId ASC, status ASC). Using full-scan fallback for pending balance.",
      error.message
    );
  }

  // Fallback for projects without the composite index yet.
  // select() keeps the payload small so this stays fast.
  const snapshot = await db
    .collection("orders")
    .where("farmerId", "==", farmerId)
    .select(
      "status",
      "payment",
      "paymentStatus",
      "financialStatus",
      "farmerWalletCredited",
      "deliveredAt",
      "subTotal",
      "products"
    )
    .get();

  return sumPendingFromDocs(snapshot.docs);
};

/* =========================================================
   XENDIT PAYOUT
   - Errors thrown BEFORE the request is sent, or a definite 4xx
     answer from Xendit, are "definite" (safe to roll back).
   - Network errors / timeouts / 5xx / 408 / 409 are "ambiguous"
     (the payout may exist). error.ambiguous = true.
   - The same idempotency key is reused for the automatic retry,
     so a retry can never create a second payout.
========================================================= */

const payoutRequest = async ({
  idempotencyKey,
  referenceId,
  accountName,
  accountNumber,
  amount,
  user,
  addressOverride = null,
}) => {
  const secretKey = getEnv("XENDIT_PAYOUT_SECRET_KEY");

  if (!secretKey) {
    throw new Error("XENDIT_PAYOUT_SECRET_KEY is not configured.");
  }

  const normalizedGcash = normalizeGcashNumber(accountNumber);
  const { givenName, surname } = splitName(accountName);

  const postalCode = String(
    user.payoutPostalCode || user.postalCode || ""
  ).trim();

  const payoutCity = String(user.municipality || user.city || "").trim();
  const payoutProvince = String(user.province || "").trim();
  const payoutStreet = String(
    user.street || user.location || user.barangay || ""
  ).trim();

  // Admin payouts supply their own address (addressOverride) and skip
  // the farmer-profile check below.
  if (!addressOverride && (!payoutCity || !payoutProvince || !payoutStreet)) {
    throw new Error(
      "Your farmer profile must have a complete address before a GCash payout can be sent."
    );
  }

  // Postal code is optional in the app. An empty string makes Xendit
  // fail validation, so the field is omitted entirely when there is no
  // valid code on file (payout account, else farmer profile).
  const address = addressOverride || {
    country: "PH",
    province_state: payoutProvince,
    city: payoutCity,
    street_line_1: payoutStreet,
  };

  if (!addressOverride && /^\d{4}$/.test(postalCode)) {
    address.postal_code = postalCode;
  }

  const payload = {
    reference_id: referenceId,

    recipient: {
      type: "INDIVIDUAL",
      given_name: givenName,
      surname,
      relationship: "SUPPLIER",

      details: {
        personal_mobile_number: `+63${normalizedGcash.slice(1)}`,
      },

      address,

      account_details: {
        currency: "PHP",
        account_country: "PH",
        account_holder_name: accountName,
        account_number: normalizedGcash,
        routing_type_1: "WALLET",
        routing_value_1: "PH_GCASH",
      },
    },

    payout_details: {
      source_currency: "PHP",
      // VERIFY in Xendit sandbox that a P100 payout is sent as 100 (not 10000).
      source_amount: Math.round(amount * 100),
      destination_currency: "PHP",
    },

    source_of_fund: "BUSINESS_REVENUE",
    purpose_code: "TRADES",

    description: `FarmGate farmer payout ${referenceId}`.slice(0, 100),

    metadata: {
      farmer_id: user.farmerId,
      payout_reference: referenceId,
    },
  };

  const sendOnce = async () => {
    let response;
    let text;

    try {
      response = await fetch(`${XENDIT_BASE_URL}/v3/payouts`, {
        method: "POST",
        signal: AbortSignal.timeout(XENDIT_TIMEOUT_MS),
        headers: {
          Authorization: `Basic ${Buffer.from(`${secretKey}:`).toString("base64")}`,
          "Content-Type": "application/json",
          "api-version": XENDIT_PAYOUT_API_VERSION,
          "idempotency-key": idempotencyKey,
        },
        body: JSON.stringify(payload),
      });

      text = await response.text();
    } catch {
      const error = new Error(
        "Could not confirm the payout request with Xendit."
      );
      error.ambiguous = true;
      throw error;
    }

    let data = {};

    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }

    if (!response.ok) {
      const error = new Error(
        data?.message ||
          data?.error_code ||
          `Xendit payout request failed with status ${response.status}.`
      );

      error.status = response.status;
      error.response = data;
      error.ambiguous =
        response.status >= 500 ||
        response.status === 408 ||
        response.status === 409;

      throw error;
    }

    return data;
  };

  let lastError;

  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      return await sendOnce();
    } catch (error) {
      lastError = error;
      if (!error.ambiguous) throw error;
    }
  }

  throw lastError;
};

/* =========================================================
   WITHDRAWAL WEBHOOK
========================================================= */

const findWithdrawal = async ({ db, payoutId, referenceId }) => {
  if (payoutId) {
    const query = await db
      .collection("farmerWithdrawals")
      .where("xenditPayoutId", "==", String(payoutId))
      .limit(1)
      .get();

    if (!query.empty) return query.docs[0];
  }

  if (referenceId) {
    const query = await db
      .collection("farmerWithdrawals")
      .where("xenditReferenceId", "==", String(referenceId))
      .limit(1)
      .get();

    if (!query.empty) return query.docs[0];
  }

  return null;
};

const applyWithdrawalWebhook = async ({ db, withdrawalDoc, data, event }) => {
  const withdrawalRef = withdrawalDoc.ref;
  const initialWithdrawal = withdrawalDoc.data() || {};

  const farmerId = String(initialWithdrawal.farmerId || "");
  const amount = roundMoney(initialWithdrawal.amount);

  if (!farmerId || amount <= 0) return;

  const walletRef = db.collection("farmerWallets").doc(farmerId);
  const summaryRef = db.collection("farmgateFinancialSummary").doc("summary");

  await db.runTransaction(async (transaction) => {
    // ---------- ALL READS FIRST ----------
    const [withdrawalSnap, walletSnap] = await Promise.all([
      transaction.get(withdrawalRef),
      transaction.get(walletRef),
    ]);

    if (!withdrawalSnap.exists) return;

    const withdrawal = withdrawalSnap.data() || {};
    const wallet = sanitizeWallet(
      farmerId,
      walletSnap.exists ? walletSnap.data() : {}
    );

    const now = new Date();
    const status = String(data?.status || "").toUpperCase();
    const currentStatus = String(withdrawal.status || "");

    const reversed = event === "v3_payout.reversed" || status === "REVERSED";

    const finalFailure =
      !reversed &&
      (event === "v3_payout.failed" ||
        event === "v3_payout.rejected" ||
        status === "FAILED" ||
        status === "REJECTED");

    const succeeded =
      !reversed &&
      !finalFailure &&
      (event === "v3_payout.succeeded" || status === "SUCCEEDED");

    // Terminal states are final (prevents double release / double credit).
    if (["failed", "rejected", "reversed"].includes(currentStatus)) return;

    // A succeeded payout can only move to "reversed".
    if (currentStatus === "succeeded" && !reversed) return;

    const gatewayFields = {
      xenditPayoutId: data?.payout_id || withdrawal.xenditPayoutId || null,
      xenditReferenceId:
        data?.reference_id || withdrawal.xenditReferenceId || null,
      xenditStatus: data?.status || null,
    };

    // ---------- REVERSED ----------
    if (reversed) {
      if (currentStatus === "succeeded") {
        // Money already left the wallet at success; give it back.
        const nextAvailable = roundMoney(wallet.availableBalance + amount);

        transaction.set(
          walletRef,
          {
            ...wallet,
            availableBalance: nextAvailable,
            totalWithdrawn: Math.max(
              0,
              roundMoney(wallet.totalWithdrawn - amount)
            ),
            updatedAt: now,
          },
          { merge: true }
        );

        transaction.set(db.collection("walletTransactions").doc(), {
          farmerId,
          type: "withdrawal_reversal",
          direction: "credit",
          amount,
          balanceAfter: nextAvailable,
          commissionReserveAfter: wallet.commissionReserveBalance,
          commissionReserveHeldAfter: wallet.commissionReserveHeld,
          withdrawalId: withdrawalDoc.id,
          status: "completed",
          description:
            "Xendit reversed the farmer GCash payout; the amount was returned to the earnings balance.",
          createdAt: now,
          completedAt: now,
        });

        transaction.set(
          summaryRef,
          {
            totalFarmerWithdrawals: FieldValue.increment(-amount),
            updatedAt: now,
          },
          { merge: true }
        );
      } else {
        // Reversed before success: only the hold is released.
        transaction.set(
          walletRef,
          {
            ...wallet,
            reservedBalance: Math.max(
              0,
              roundMoney(wallet.reservedBalance - amount)
            ),
            updatedAt: now,
          },
          { merge: true }
        );
      }

      if (withdrawal.walletTransactionId) {
        transaction.set(
          db.collection("walletTransactions").doc(withdrawal.walletTransactionId),
          {
            status: "reversed",
            completedAt: now,
            description: "Farmer GCash withdrawal reversed.",
          },
          { merge: true }
        );
      }

      transaction.set(
        withdrawalRef,
        {
          status: "reversed",
          ...gatewayFields,
          failureCode: data?.failure_code || null,
          failureReason: data?.failure_reason || null,
          failedAt: now,
          completedAt: now,
          updatedAt: now,
        },
        { merge: true }
      );

      return;
    }

    // ---------- FAILED / REJECTED ----------
    if (finalFailure) {
      // Release the hold only; available was never reduced.
      transaction.set(
        walletRef,
        {
          ...wallet,
          reservedBalance: Math.max(
            0,
            roundMoney(wallet.reservedBalance - amount)
          ),
          updatedAt: now,
        },
        { merge: true }
      );

      if (withdrawal.walletTransactionId) {
        transaction.set(
          db.collection("walletTransactions").doc(withdrawal.walletTransactionId),
          {
            status: "failed",
            completedAt: now,
            description:
              "Farmer GCash withdrawal failed/rejected; held amount released.",
          },
          { merge: true }
        );
      }

      transaction.set(
        withdrawalRef,
        {
          status: status === "REJECTED" ? "rejected" : "failed",
          ...gatewayFields,
          failureCode: data?.failure_code || null,
          failureReason: data?.failure_reason || null,
          failedAt: now,
          updatedAt: now,
        },
        { merge: true }
      );

      return;
    }

    // ---------- SUCCEEDED ----------
    if (succeeded) {
      const nextReserved = Math.max(
        0,
        roundMoney(wallet.reservedBalance - amount)
      );
      const nextAvailable = Math.max(
        0,
        roundMoney(wallet.availableBalance - amount)
      );

      transaction.set(
        walletRef,
        {
          ...wallet,
          availableBalance: nextAvailable,
          reservedBalance: nextReserved,
          totalWithdrawn: roundMoney(wallet.totalWithdrawn + amount),
          updatedAt: now,
        },
        { merge: true }
      );

      transaction.set(
        withdrawalRef,
        {
          status: "succeeded",
          ...gatewayFields,
          completedAt: now,
          updatedAt: now,
        },
        { merge: true }
      );

      if (withdrawal.walletTransactionId) {
        transaction.set(
          db.collection("walletTransactions").doc(withdrawal.walletTransactionId),
          {
            status: "completed",
            balanceAfter: nextAvailable,
            completedAt: now,
            description: "Farmer GCash withdrawal completed.",
          },
          { merge: true }
        );
      }

      transaction.set(
        summaryRef,
        {
          totalFarmerWithdrawals: FieldValue.increment(amount),
          updatedAt: now,
        },
        { merge: true }
      );

      return;
    }

    // ---------- STILL IN PROGRESS ----------
    const nextStatus =
      event === "v3_payout.pending_compliance" ||
      status === "PENDING_COMPLIANCE_REVIEW"
        ? "pending_compliance"
        : "processing";

    transaction.set(
      withdrawalRef,
      {
        status: nextStatus,
        ...gatewayFields,
        processingAt: withdrawal.processingAt || now,
        updatedAt: now,
      },
      { merge: true }
    );
  });
};

const findAdminWithdrawal = async ({ db, payoutId, referenceId }) => {
  if (payoutId) {
    const query = await db
      .collection("adminWithdrawals")
      .where("xenditPayoutId", "==", String(payoutId))
      .limit(1)
      .get();

    if (!query.empty) return query.docs[0];
  }

  if (referenceId) {
    const query = await db
      .collection("adminWithdrawals")
      .where("xenditReferenceId", "==", String(referenceId))
      .limit(1)
      .get();

    if (!query.empty) return query.docs[0];
  }

  return null;
};

/* Mirrors applyWithdrawalWebhook for the shared admin wallet:
   request -> pending += amount; success -> pending -= amount,
   available -= amount; failure -> pending -= amount;
   reversal after success -> available += amount. */
const applyAdminWithdrawalWebhook = async ({ db, withdrawalDoc, data, event }) => {
  const withdrawalRef = withdrawalDoc.ref;
  const initialWithdrawal = withdrawalDoc.data() || {};
  const amount = roundMoney(initialWithdrawal.amount);

  if (amount <= 0) return;

  const walletRef = db.collection("adminWallets").doc(ADMIN_WALLET_ID);

  await db.runTransaction(async (transaction) => {
    const [withdrawalSnap, walletSnap] = await Promise.all([
      transaction.get(withdrawalRef),
      transaction.get(walletRef),
    ]);

    if (!withdrawalSnap.exists) return;

    const withdrawal = withdrawalSnap.data() || {};
    const wallet = sanitizeAdminWallet(
      walletSnap.exists ? walletSnap.data() : {}
    );
    const now = new Date();
    const status = String(data?.status || "").toUpperCase();
    const currentStatus = String(withdrawal.status || "");
    const reversed = event === "v3_payout.reversed" || status === "REVERSED";
    const finalFailure =
      !reversed &&
      (event === "v3_payout.failed" ||
        event === "v3_payout.rejected" ||
        status === "FAILED" ||
        status === "REJECTED");
    const succeeded =
      !reversed &&
      !finalFailure &&
      (event === "v3_payout.succeeded" || status === "SUCCEEDED");

    if (["failed", "rejected", "reversed"].includes(currentStatus)) return;
    if (currentStatus === "succeeded" && !reversed) return;

    const gatewayFields = {
      xenditPayoutId: data?.payout_id || withdrawal.xenditPayoutId || null,
      xenditReferenceId:
        data?.reference_id || withdrawal.xenditReferenceId || null,
      xenditStatus: data?.status || null,
    };

    const releaseHold = () =>
      transaction.set(
        walletRef,
        {
          ...wallet,
          pendingWithdrawal: Math.max(
            0,
            roundMoney(wallet.pendingWithdrawal - amount)
          ),
          updatedAt: now,
        },
        { merge: true }
      );

    const markLedger = (ledgerStatus, description) => {
      if (withdrawal.walletTransactionId) {
        transaction.set(
          db.collection("walletTransactions").doc(withdrawal.walletTransactionId),
          { status: ledgerStatus, completedAt: now, description },
          { merge: true }
        );
      }
    };

    if (reversed) {
      if (currentStatus === "succeeded") {
        const nextAvailable = roundMoney(wallet.availableBalance + amount);
        transaction.set(
          walletRef,
          {
            ...wallet,
            availableBalance: nextAvailable,
            totalWithdrawn: Math.max(
              0,
              roundMoney(wallet.totalWithdrawn - amount)
            ),
            updatedAt: now,
          },
          { merge: true }
        );
        transaction.set(db.collection("walletTransactions").doc(), {
          farmerId: ADMIN_LEDGER_ID,
          type: "withdrawal_reversal",
          direction: "credit",
          amount,
          balanceAfter: nextAvailable,
          withdrawalId: withdrawalDoc.id,
          reference: withdrawal.xenditReferenceId || null,
          status: "completed",
          description: "Xendit reversed the admin GCash payout; amount returned.",
          createdAt: now,
          completedAt: now,
        });
      } else {
        releaseHold();
      }

      markLedger("reversed", "Admin GCash withdrawal reversed.");
      transaction.set(
        withdrawalRef,
        {
          status: "reversed",
          ...gatewayFields,
          failureCode: data?.failure_code || null,
          failureReason: data?.failure_reason || null,
          failedAt: now,
          completedAt: now,
          updatedAt: now,
        },
        { merge: true }
      );
      return;
    }

    if (finalFailure) {
      releaseHold();
      markLedger("failed", "Admin GCash withdrawal failed; held amount released.");
      transaction.set(
        withdrawalRef,
        {
          status: status === "REJECTED" ? "rejected" : "failed",
          ...gatewayFields,
          failureCode: data?.failure_code || null,
          failureReason: data?.failure_reason || null,
          failedAt: now,
          updatedAt: now,
        },
        { merge: true }
      );
      return;
    }

    if (succeeded) {
      const nextAvailable = Math.max(
        0,
        roundMoney(wallet.availableBalance - amount)
      );
      transaction.set(
        walletRef,
        {
          ...wallet,
          availableBalance: nextAvailable,
          pendingWithdrawal: Math.max(
            0,
            roundMoney(wallet.pendingWithdrawal - amount)
          ),
          totalWithdrawn: roundMoney(wallet.totalWithdrawn + amount),
          updatedAt: now,
        },
        { merge: true }
      );
      transaction.set(
        withdrawalRef,
        {
          status: "succeeded",
          ...gatewayFields,
          completedAt: now,
          updatedAt: now,
        },
        { merge: true }
      );
      markLedger("completed", "Admin GCash withdrawal completed.");
      return;
    }

    transaction.set(
      withdrawalRef,
      {
        status:
          event === "v3_payout.pending_compliance" ||
          status === "PENDING_COMPLIANCE_REVIEW"
            ? "pending_compliance"
            : "processing",
        ...gatewayFields,
        processingAt: withdrawal.processingAt || now,
        updatedAt: now,
      },
      { merge: true }
    );
  });
};

/* =========================================================
   COMMISSION DEPOSIT WEBHOOK
========================================================= */

const findCommissionDeposit = async ({
  db,
  depositId,
  paymentRequestId,
  referenceId,
}) => {
  if (depositId) {
    const snap = await db
      .collection("farmerCommissionDeposits")
      .doc(String(depositId))
      .get();

    if (snap.exists) return snap;
  }

  if (paymentRequestId) {
    const query = await db
      .collection("farmerCommissionDeposits")
      .where("xenditPaymentRequestId", "==", String(paymentRequestId))
      .limit(1)
      .get();

    if (!query.empty) return query.docs[0];
  }

  if (referenceId) {
    const query = await db
      .collection("farmerCommissionDeposits")
      .where("xenditReferenceId", "==", String(referenceId))
      .limit(1)
      .get();

    if (!query.empty) return query.docs[0];
  }

  return null;
};

const handleCommissionDepositWebhook = async ({ db, event, data }) => {
  const metadata = data?.metadata || {};

  if (String(metadata.type || "") !== "farmer_commission_deposit") {
    return { handled: false };
  }

  const depositDoc = await findCommissionDeposit({
    db,
    depositId: metadata.depositId || metadata.deposit_id,
    paymentRequestId: data?.payment_request_id,
    referenceId: data?.reference_id,
  });

  if (!depositDoc) {
    console.warn("COMMISSION DEPOSIT WEBHOOK: deposit not found.", {
      event,
      depositId: metadata.depositId || metadata.deposit_id,
      paymentRequestId: data?.payment_request_id,
      referenceId: data?.reference_id,
    });

    return { handled: true, found: false };
  }

  const depositRef = depositDoc.ref;
  const deposit = depositDoc.data() || {};

  const farmerId = String(deposit.farmerId || metadata.farmerId || "");
  const depositAmount = roundMoney(deposit.amount);

  if (!farmerId || depositAmount <= 0) {
    throw new Error("Invalid farmer commission deposit record.");
  }

  const gatewayFields = {
    xenditPaymentId: data?.payment_id || deposit.xenditPaymentId || null,
    xenditPaymentRequestId:
      data?.payment_request_id || deposit.xenditPaymentRequestId || null,
    xenditReferenceId: data?.reference_id || deposit.xenditReferenceId || null,
  };

  // Never overwrite a completed deposit.
  const markIfNotCompleted = async (fields) =>
    db.runTransaction(async (transaction) => {
      const fresh = await transaction.get(depositRef);

      if (!fresh.exists) return false;
      if ((fresh.data() || {}).status === "completed") return false;

      transaction.set(depositRef, fields, { merge: true });
      return true;
    });

  // ---------- FAILURE ----------
  if (event === "payment.failure") {
    const updated = await markIfNotCompleted({
      status: "failed",
      ...gatewayFields,
      xenditPaymentStatus: data?.status || "FAILED",
      failureCode: data?.failure_code || data?.error_code || null,
      failureReason:
        data?.failure_reason || data?.failure_message || data?.message || null,
      failedAt: new Date(),
      updatedAt: new Date(),
    });

    return updated
      ? { handled: true, failed: true }
      : { handled: true, alreadyCompleted: true };
  }

  // ---------- NOT A SUCCESSFUL CAPTURE ----------
  if (event !== "payment.capture" || data?.status !== "SUCCEEDED") {
    await depositRef.set(
      {
        xenditPaymentStatus: data?.status || null,
        ...gatewayFields,
        updatedAt: new Date(),
      },
      { merge: true }
    );

    return { handled: true, acknowledged: true };
  }

  // ---------- SUCCESSFUL CAPTURE: VALIDATE ----------
  const capturedAmount = normalizeAmount(
    data?.captures?.find((capture) => capture?.status === "SUCCEEDED")
      ?.capture_amount ??
      data?.captures?.[0]?.capture_amount ??
      data?.request_amount
  );

  const requestIdMismatch =
    deposit.xenditPaymentRequestId &&
    data?.payment_request_id &&
    deposit.xenditPaymentRequestId !== data.payment_request_id;

  const amountMismatch =
    !Number.isFinite(capturedAmount) ||
    Math.abs(capturedAmount - depositAmount) > 0.01;

  if (requestIdMismatch || amountMismatch) {
    await markIfNotCompleted({
      status: "manual_review",
      ...gatewayFields,
      xenditPaymentStatus: data?.status || "SUCCEEDED",
      paidAt: new Date(),
      fulfillmentError: requestIdMismatch
        ? "Commission deposit payment request mismatch."
        : "Commission deposit amount mismatch.",
      failureReason: requestIdMismatch
        ? "Commission deposit payment request mismatch."
        : "Commission deposit amount mismatch.",
      updatedAt: new Date(),
    });

    return { handled: true, manualReview: true };
  }

  // ---------- CREDIT THE RESERVE (idempotent) ----------
  const walletRef = db.collection("farmerWallets").doc(farmerId);

  await db.runTransaction(async (transaction) => {
    const [freshDepositSnap, walletSnap] = await Promise.all([
      transaction.get(depositRef),
      transaction.get(walletRef),
    ]);

    if (!freshDepositSnap.exists) {
      throw new Error("Commission deposit record no longer exists.");
    }

    if ((freshDepositSnap.data() || {}).status === "completed") return;

    const wallet = sanitizeWallet(
      farmerId,
      walletSnap.exists ? walletSnap.data() : {}
    );

    const now = new Date();

    const nextReserve = roundMoney(
      wallet.commissionReserveBalance + depositAmount
    );

    transaction.set(
      walletRef,
      {
        ...wallet,
        commissionReserveBalance: nextReserve,
        totalCommissionDeposited: roundMoney(
          wallet.totalCommissionDeposited + depositAmount
        ),
        updatedAt: now,
      },
      { merge: true }
    );

    const walletTransactionRef = db.collection("walletTransactions").doc();

    transaction.set(walletTransactionRef, {
      farmerId,
      type: "commission_deposit",
      direction: "credit",
      amount: depositAmount,
      balanceAfter: wallet.availableBalance,
      commissionReserveAfter: nextReserve,
      commissionReserveHeldAfter: wallet.commissionReserveHeld,
      depositId: freshDepositSnap.id,
      status: "completed",
      description: "Commission reserve deposit for FarmGate COD commissions.",
      createdAt: now,
      completedAt: now,
    });

    transaction.set(
      depositRef,
      {
        status: "completed",
        ...gatewayFields,
        xenditPaymentStatus: data?.status || "SUCCEEDED",
        paidAt: now,
        walletTransactionId: walletTransactionRef.id,
        updatedAt: now,
      },
      { merge: true }
    );

    transaction.set(
      db.collection("farmgateFinancialSummary").doc("summary"),
      {
        totalFarmerCommissionDeposits: FieldValue.increment(depositAmount),
        updatedAt: now,
      },
      { merge: true }
    );
  });

  return { handled: true, completed: true };
};

/* =========================================================
   ROUTER
========================================================= */

const createWalletRouter = ({ db, auth, inventory }) => {
  const router = express.Router();

  const { planInventory, applyInventoryPlans, planRestock, applyRestock } =
    inventory || {};

  if (
    !planInventory ||
    !applyInventoryPlans ||
    !planRestock ||
    !applyRestock
  ) {
    throw new Error("createWalletRouter requires the inventory helpers.");
  }

  const loadFarmerTransactions = async (farmerId) => {
    const base = db
      .collection("walletTransactions")
      .where("farmerId", "==", farmerId);

    const mapDocs = (snapshot) =>
      snapshot.docs.map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }));

    try {
      // Needs composite index: farmerId ASC + createdAt DESC.
      const snapshot = await base
        .orderBy("createdAt", "desc")
        .limit(TRANSACTION_LIMIT)
        .get();

      return mapDocs(snapshot);
    } catch (error) {
      if (!isIndexMissingError(error)) throw error;

      console.warn(
        "walletTransactions needs a composite index (farmerId ASC, createdAt DESC). Using bounded fallback.",
        error.message
      );

      // Bounded fallback: never pull the whole history. Over-fetch a bit,
      // sort in memory, then cut to the page size.
      const snapshot = await base.limit(TRANSACTION_LIMIT * 4).get();

      return mapDocs(snapshot)
        .sort((a, b) => toMillis(b.createdAt) - toMillis(a.createdAt))
        .slice(0, TRANSACTION_LIMIT);
    }
  };

  const loadPayoutAccount = async (farmerId) => {
    const snap = await db
      .collection("farmerPayoutAccounts")
      .doc(farmerId)
      .get();

    if (!snap.exists) return null;

    const data = snap.data() || {};

    return {
      farmerId,
      method: "gcash",
      channel: "PH_GCASH",
      accountName: data.accountName || "",
      postalCode: data.postalCode || "",
      accountNumberMasked: safeMaskGcashNumber(
        data.accountNumberMasked,
        data.accountNumber
      ),
      status: data.status || "active",
      createdAt: data.createdAt || null,
      updatedAt: data.updatedAt || null,
    };
  };

  // ------------------------------------------------------------
  // GET FARMER WALLET (fast: wallet document only)
  // ------------------------------------------------------------
  router.get("/me", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);
      const farmerId = decoded.uid;

      const ref = db.collection("farmerWallets").doc(farmerId);
      const snap = await ref.get();

      const wallet = sanitizeWallet(farmerId, snap.exists ? snap.data() : {});

      if (!snap.exists) {
        await ref.set({
          ...wallet,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
      }

      return res.json({
        success: true,
        wallet,
        withdrawableAmount: getWithdrawableAmount(wallet),
        minimumCommissionDeposit: getMinimumCommissionDeposit(),
        minimumWithdrawal: getMinimumWithdrawal(),
      });
    } catch (error) {
      console.error("GET FARMER WALLET ERROR:", error);

      return sendWalletError(res, error, 500);
    }
  });

  // ------------------------------------------------------------
  // GET WALLET OVERVIEW (single roundtrip for the mobile wallet
  // screen: 1 auth check, then wallet + payout + history in parallel)
  // ------------------------------------------------------------
  router.get("/overview", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);
      const farmerId = decoded.uid;

      const walletRef = db.collection("farmerWallets").doc(farmerId);

      const [walletSnap, payoutAccount, transactions] = await Promise.all([
        walletRef.get(),
        loadPayoutAccount(farmerId),
        loadFarmerTransactions(farmerId),
      ]);

      const wallet = sanitizeWallet(
        farmerId,
        walletSnap.exists ? walletSnap.data() : {}
      );

      if (!walletSnap.exists) {
        await walletRef.set({
          ...wallet,
          createdAt: new Date(),
          updatedAt: new Date(),
        });
      }

      return res.json({
        success: true,
        wallet,
        payoutAccount,
        transactions,
        withdrawableAmount: getWithdrawableAmount(wallet),
        minimumCommissionDeposit: getMinimumCommissionDeposit(),
        minimumWithdrawal: getMinimumWithdrawal(),
      });
    } catch (error) {
      console.error("GET WALLET OVERVIEW ERROR:", error);

      return sendWalletError(res, error, 500);
    }
  });

  // ------------------------------------------------------------
  // GET PENDING GCASH EARNINGS (computed from orders)
  // ------------------------------------------------------------
  router.get("/pending-gcash", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);

      const pendingBalance = await getPendingProductBalance(db, decoded.uid);

      return res.json({ success: true, pendingBalance });
    } catch (error) {
      console.error("GET PENDING GCASH EARNINGS ERROR:", error);

      return res.status(400).json({
        success: false,
        error: error.message || "Unable to calculate pending GCash earnings.",
      });
    }
  });

  // ------------------------------------------------------------
  // GET WALLET TRANSACTIONS (latest 50)
  // ------------------------------------------------------------
  router.get("/transactions", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);

      const transactions = await loadFarmerTransactions(decoded.uid);

      return res.json({ success: true, transactions });
    } catch (error) {
      console.error("GET WALLET TRANSACTIONS ERROR:", error);

      return res.status(401).json({ success: false, error: error.message });
    }
  });

  // ------------------------------------------------------------
  // GET PAYOUT ACCOUNT
  // ------------------------------------------------------------
  router.get("/payout-account", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);

      const snap = await db
        .collection("farmerPayoutAccounts")
        .doc(decoded.uid)
        .get();

      if (!snap.exists) {
        return res.json({ success: true, payoutAccount: null });
      }

      const data = snap.data() || {};

      return res.json({
        success: true,
        payoutAccount: {
          farmerId: decoded.uid,
          method: "gcash",
          channel: "PH_GCASH",
          accountName: data.accountName || "",
          postalCode: data.postalCode || "",
          accountNumberMasked:
            data.accountNumberMasked ||
            maskGcashNumber(data.accountNumber || ""),
          status: data.status || "active",
          createdAt: data.createdAt || null,
          updatedAt: data.updatedAt || null,
        },
      });
    } catch (error) {
      console.error("GET PAYOUT ACCOUNT ERROR:", error);

      return res.status(401).json({ success: false, error: error.message });
    }
  });

  // ------------------------------------------------------------
  // SAVE PAYOUT ACCOUNT
  // ------------------------------------------------------------
  router.put("/payout-account", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);

      const accountName = String(req.body?.accountName || "").trim();
      const accountNumber = normalizeGcashNumber(req.body?.accountNumber);

      const userSnap = await db.collection("users").doc(decoded.uid).get();
      const user = userSnap.exists ? userSnap.data() || {} : {};

      const ref = db.collection("farmerPayoutAccounts").doc(decoded.uid);
      const existing = await ref.get();
      const existingData = existing.exists ? existing.data() || {} : {};

      // Postal code is no longer collected in the app UI. Keep the stored
      // one, else the farmer profile value, else empty (withdraw validates
      // before any payout is sent).
      const postalCode = String(
        req.body?.postalCode ||
          existingData.postalCode ||
          user.postalCode ||
          ""
      ).trim();

      if (accountName.length < 3) {
        return res.status(400).json({
          success: false,
          error: "Enter the GCash account name.",
        });
      }

      if (postalCode !== "" && !/^\d{4}$/.test(postalCode)) {
        return res.status(400).json({
          success: false,
          error: "Enter a valid 4-digit Philippine postal code for payouts.",
        });
      }

      const now = new Date();
      const createdAt = existing.exists
        ? existing.data()?.createdAt || now
        : now;

      const accountNumberMasked = maskGcashNumber(accountNumber);

      await ref.set(
        {
          farmerId: decoded.uid,
          method: "gcash",
          channel: "PH_GCASH",
          accountName,
          accountNumber,
          postalCode,
          accountNumberMasked,
          status: "active",
          createdAt,
          updatedAt: now,
        },
        { merge: true }
      );

      return res.json({
        success: true,
        payoutAccount: {
          farmerId: decoded.uid,
          method: "gcash",
          channel: "PH_GCASH",
          accountName,
          postalCode,
          accountNumberMasked,
          status: "active",
          createdAt,
          updatedAt: now,
        },
      });
    } catch (error) {
      console.error("SAVE PAYOUT ACCOUNT ERROR:", error);

      return res.status(400).json({ success: false, error: error.message });
    }
  });

  // ------------------------------------------------------------
  // CREATE COMMISSION RESERVE DEPOSIT
  // The reserve is credited ONLY by the webhook after payment.capture.
  // ------------------------------------------------------------
  router.post("/deposit", async (req, res) => {
    let depositRef = null;

    try {
      const { decoded } = await requireFarmer(req, auth, db);

      const amount = normalizeAmount(req.body?.amount);
      const minimumDeposit = getMinimumCommissionDeposit();

      if (!Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({
          success: false,
          error: "Enter a valid deposit amount.",
        });
      }

      if (amount < minimumDeposit) {
        return res.status(400).json({
          success: false,
          error: `Minimum commission reserve deposit is ₱${minimumDeposit.toFixed(2)}.`,
        });
      }

      if (amount > MAX_COMMISSION_DEPOSIT) {
        return res.status(400).json({
          success: false,
          error: `Maximum commission reserve deposit is ₱${MAX_COMMISSION_DEPOSIT.toFixed(2)}.`,
        });
      }

      const publicBaseUrl = String(process.env.PUBLIC_BASE_URL || "")
        .trim()
        .replace(/\/+$/, "");

      if (!publicBaseUrl) {
        return res.status(500).json({
          success: false,
          error: "PUBLIC_BASE_URL is not configured.",
        });
      }

      depositRef = db.collection("farmerCommissionDeposits").doc();

      const depositId = depositRef.id;
      const referenceId = `FG-DEP-${depositId}-${Date.now()}`;

      const successReturnUrl = `${publicBaseUrl}/payment/success?type=farmer_deposit&depositId=${encodeURIComponent(depositId)}`;
      const failureReturnUrl = `${publicBaseUrl}/payment/failure?type=farmer_deposit&depositId=${encodeURIComponent(depositId)}`;

      await depositRef.set({
        farmerId: decoded.uid,
        amount,
        status: "pending",
        referenceId,
        xenditReferenceId: referenceId,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const paymentRequest = await xenditRequest("/v3/payment_requests", {
        method: "POST",
        headers: {
          "idempotency-key": createIdempotencyKey("FG-DEP"),
        },
        body: JSON.stringify({
          reference_id: referenceId,
          type: "PAY",
          country: "PH",
          currency: "PHP",
          request_amount: amount,
          capture_method: "AUTOMATIC",
          channel_code: "GCASH",
          channel_properties: {
            success_return_url: successReturnUrl,
            failure_return_url: failureReturnUrl,
          },
          description: `FarmGate Commission Reserve Deposit ${depositId}`,
          metadata: {
            type: "farmer_commission_deposit",
            depositId,
            farmerId: decoded.uid,
            amount: String(amount),
          },
        }),
      });

      const paymentRequestId =
        paymentRequest.payment_request_id || paymentRequest.id || null;

      const redirectUrl = getRedirectUrl(paymentRequest.actions);

      if (!paymentRequestId || !redirectUrl) {
        await depositRef.update({
          status: "failed",
          failureReason: "Xendit did not return a usable payment redirect.",
          updatedAt: new Date(),
        });

        return res.status(502).json({
          success: false,
          error: "Xendit did not return a customer redirect URL.",
        });
      }

      await depositRef.update({
        xenditPaymentRequestId: paymentRequestId,
        xenditReferenceId: paymentRequest.reference_id || referenceId,
        xenditPaymentStatus: paymentRequest.status || "PENDING",
        paymentRequestCreatedAt: new Date(),
        updatedAt: new Date(),
      });

      return res.json({
        success: true,
        depositId,
        amount,
        paymentRequestId,
        referenceId: paymentRequest.reference_id || referenceId,
        paymentStatus: paymentRequest.status || "PENDING",
        redirectUrl,
      });
    } catch (error) {
      console.error("CREATE COMMISSION DEPOSIT ERROR:", error);

      // Do not leave an orphaned "pending" deposit when Xendit rejected the request.
      if (depositRef && error.status) {
        try {
          await depositRef.update({
            status: "failed",
            failureReason: error.message || "Payment request failed.",
            updatedAt: new Date(),
          });
        } catch (updateError) {
          console.error("MARK DEPOSIT FAILED ERROR:", updateError);
        }
      }

      return res.status(error.status || 400).json({
        success: false,
        error:
          error.message || "Unable to create commission reserve deposit.",
        details: error.response || null,
      });
    }
  });

  // ------------------------------------------------------------
  // GET COMMISSION DEPOSIT STATUS
  // ------------------------------------------------------------
  router.get("/deposits/:depositId", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);

      const depositId = String(req.params.depositId || "").trim();

      if (!depositId) {
        return res
          .status(400)
          .json({ success: false, error: "Deposit ID is required." });
      }

      const depositSnap = await db
        .collection("farmerCommissionDeposits")
        .doc(depositId)
        .get();

      if (!depositSnap.exists) {
        return res
          .status(404)
          .json({ success: false, error: "Commission deposit not found." });
      }

      const deposit = depositSnap.data() || {};

      if (deposit.farmerId !== decoded.uid) {
        return res.status(403).json({
          success: false,
          error: "You are not authorized to view this deposit.",
        });
      }

      const walletSnap = await db
        .collection("farmerWallets")
        .doc(decoded.uid)
        .get();

      const wallet = sanitizeWallet(
        decoded.uid,
        walletSnap.exists ? walletSnap.data() : {}
      );

      return res.json({
        success: true,
        deposit: {
          id: depositSnap.id,
          farmerId: decoded.uid,
          amount: roundMoney(deposit.amount),
          status: deposit.status || "pending",
          referenceId: deposit.referenceId || null,
          xenditPaymentStatus: deposit.xenditPaymentStatus || null,
          failureReason: deposit.failureReason || null,
          createdAt: deposit.createdAt || null,
          updatedAt: deposit.updatedAt || null,
        },
        commissionReserveBalance: wallet.commissionReserveBalance,
      });
    } catch (error) {
      console.error("GET COMMISSION DEPOSIT STATUS ERROR:", error);

      return res.status(400).json({
        success: false,
        error: error.message || "Unable to load deposit status.",
      });
    }
  });

  // ------------------------------------------------------------
  // COD ELIGIBILITY (advisory only; /accept is the real check)
  // ------------------------------------------------------------
  router.get("/cod-eligibility/:orderId", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);

      const orderSnap = await db
        .collection("orders")
        .doc(String(req.params.orderId))
        .get();

      if (!orderSnap.exists) {
        return res
          .status(404)
          .json({ success: false, error: "Order not found." });
      }

      const order = orderSnap.data() || {};

      if (order.farmerId !== decoded.uid) {
        return res.status(403).json({
          success: false,
          error: "You are not authorized to accept this order.",
        });
      }

      if (order.payment !== "cod") {
        return res.json({
          success: true,
          eligible: true,
          requiredCommission: 0,
          commissionReserveBalance: 0,
        });
      }

      const commission = getCodCommission(order);

      const walletSnap = await db
        .collection("farmerWallets")
        .doc(decoded.uid)
        .get();

      const wallet = sanitizeWallet(
        decoded.uid,
        walletSnap.exists ? walletSnap.data() : {}
      );

      return res.json({
        success: true,
        eligible: wallet.commissionReserveBalance >= commission.amount,
        commissionRate: commission.rate,
        subtotal: commission.subtotal,
        requiredCommission: commission.amount,
        commissionReserveBalance: wallet.commissionReserveBalance,
        commissionReserveHeld: wallet.commissionReserveHeld,
      });
    } catch (error) {
      console.error("COD ELIGIBILITY ERROR:", error);

      return res.status(400).json({ success: false, error: error.message });
    }
  });

  // ------------------------------------------------------------
  // ACCEPT ORDER
  // COD  : re-priced on the server, the commission is held from the
  //        reserve, and STOCK IS DEDUCTED NOW (at acceptance), atomically.
  // GCash: nothing is held; stock is deducted when payment is captured.
  // ------------------------------------------------------------
  router.post("/orders/:orderId/accept", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);

      const orderRef = db.collection("orders").doc(String(req.params.orderId));
      const walletRef = db.collection("farmerWallets").doc(decoded.uid);

      const result = await db.runTransaction(async (transaction) => {
        // ---------- READS ----------
        const [orderSnap, walletSnap] = await Promise.all([
          transaction.get(orderRef),
          transaction.get(walletRef),
        ]);

        if (!orderSnap.exists) throw new Error("Order not found.");

        const order = orderSnap.data() || {};

        if (order.farmerId !== decoded.uid) {
          throw new Error("You are not authorized to accept this order.");
        }

        if (order.status !== "pending") {
          throw new Error("Only pending orders can be accepted.");
        }

        if (order.payment !== "cod" && order.payment !== "gcash") {
          throw new Error("Order has an invalid payment method.");
        }

        const wallet = sanitizeWallet(
          decoded.uid,
          walletSnap.exists ? walletSnap.data() : {}
        );

        const now = new Date();
        const rate = getCommissionRate();

        let pricing = null;
        let inventoryPlan = null;
        let nextWallet = wallet;
        let reservationAmount = 0;
        let commissionAmount;

        if (order.payment === "cod") {
          if (order.inventoryFulfilled === true) {
            throw new Error("Stock was already deducted for this order.");
          }

          pricing = await priceOrderOnServer(transaction, db, order);

          reservationAmount = roundMoney(pricing.subtotal * rate);
          commissionAmount = reservationAmount;

          if (wallet.commissionReserveBalance + 0.001 < reservationAmount) {
            throw new Error(
              `Insufficient commission reserve. Required: ₱${reservationAmount.toFixed(2)}. Available: ₱${wallet.commissionReserveBalance.toFixed(2)}. Please deposit first.`
            );
          }

          // Reads batches / harvest records and throws STOCK_UNAVAILABLE
          // if there is not enough stock. Still reads only.
          inventoryPlan = await planInventory(transaction, {
            ...order,
            products: pricing.products,
          });

          nextWallet = {
            ...wallet,
            commissionReserveBalance: Math.max(
              0,
              roundMoney(wallet.commissionReserveBalance - reservationAmount)
            ),
            commissionReserveHeld: roundMoney(
              wallet.commissionReserveHeld + reservationAmount
            ),
            updatedAt: now,
          };

          // ---------- WRITES ----------
          applyInventoryPlans(transaction, inventoryPlan.plans);

          transaction.set(walletRef, nextWallet, { merge: true });

          transaction.set(db.collection("walletTransactions").doc(), {
            farmerId: decoded.uid,
            type: "cod_commission_reserved",
            direction: "memo",
            amount: reservationAmount,
            balanceAfter: wallet.availableBalance,
            commissionReserveAfter: nextWallet.commissionReserveBalance,
            commissionReserveHeldAfter: nextWallet.commissionReserveHeld,
            orderId: orderSnap.id,
            orderNumber: order.orderNumber || null,
            status: "completed",
            description: `Reserved COD commission for ${order.orderNumber || orderSnap.id}.`,
            createdAt: now,
            completedAt: now,
          });
        } else {
          // GCash: provisional totals. The authoritative re-price happens in
          // /create-payment (validateOrderForPayment). Still, the delivery
          // address must be validated NOW so out-of-Bulacan orders are blocked
          // at accept and the order stays pending with a clear error.
          commissionAmount = roundMoney(getOrderSubtotal(order) * rate);
          if (order.delivery === "delivery") {
            const farmerSnap = await transaction.get(
              db.collection("users").doc(String(order.farmerId))
            );
            const farmerProfile = farmerSnap.exists ? farmerSnap.data() : {};
            // Throws DeliveryFeeError when undeliverable -> transaction aborts,
            // order stays pending, caller returns 400 with the message.
            const dq = computeDeliveryForOrder({ farmerProfile, order });
            pricing = {
              products: order.products,
              subtotal: getOrderSubtotal(order),
              deliveryFee: dq.deliveryFee,
              distanceKm: dq.distanceKm,
              deliveryTier: dq.tier,
              deliveryLegacy: dq.legacy === true,
              total: roundMoney(getOrderSubtotal(order) + dq.deliveryFee),
            };
          }
        }

        transaction.update(orderRef, {
          status: "accepted",
          farmerDecision: "accepted",
          farmerDecisionAt: now,

          paymentStatus: order.paymentStatus || "pending",

          ...(pricing
            ? order.payment === "cod"
              ? {
                  products: inventoryPlan.updatedProducts,
                  subTotal: pricing.subtotal,
                  deliveryFee: pricing.deliveryFee,
                  distanceKm: pricing.distanceKm ?? null,
                  deliveryTier: pricing.deliveryTier ?? null,
                  total: pricing.total,
                  serverValidated: true,
                  serverValidatedAt: now,

                  inventoryFulfilled: true,
                  fulfillmentStatus: "fulfilled",
                  inventoryFulfilledAt: now,
                }
              : {
                  // GCash provisional delivery quote (authoritative at payment).
                  deliveryFee: pricing.deliveryFee,
                  distanceKm: pricing.distanceKm ?? null,
                  deliveryTier: pricing.deliveryTier ?? null,
                  total: pricing.total,
                  inventoryFulfilled: false,
                  fulfillmentStatus: "pending",
                }
            : {
                inventoryFulfilled: false,
                fulfillmentStatus: "pending",
              }),

          commissionRate: rate,
          commissionAmount,
          commissionStatus: "pending",

          codCommissionReserved: reservationAmount,
          codCommissionReservationStatus:
            order.payment === "cod" ? "reserved" : "not_applicable",

          updatedAt: now,
        });

        return {
          orderId: orderSnap.id,
          status: "accepted",
          codCommissionReserved: reservationAmount,
          commissionReserveBalance: nextWallet.commissionReserveBalance,
          commissionReserveHeld: nextWallet.commissionReserveHeld,
        };
      });

      return res.json({ success: true, ...result });
    } catch (error) {
      console.error("ACCEPT ORDER ERROR:", error);

      // DeliveryFeeError keeps the order pending with a clear, actionable message.
      return res
        .status(error.code === "STOCK_UNAVAILABLE" ? 409 : 400)
        .json({
          success: false,
          error: error.message,
          ...(error?.name === "DeliveryFeeError" && error?.code
            ? { code: error.code }
            : {}),
        });
    }
  });

  // ------------------------------------------------------------
  // DELIVERY QUOTE (authoritative preview, never trusts client fee/distance)
  // POST /wallet/delivery/quote { farmerId, address: {province,city,barangay}, delivery? }
  // Farm barangay is read from users/{farmerId}; buyer barangay from address.
  // ------------------------------------------------------------
  router.post("/delivery/quote", async (req, res) => {
    try {
      await getAuthUser(req, auth);

      const farmerId = String(req.body?.farmerId || "").trim();
      const address = req.body?.address || null;
      const delivery = req.body?.delivery || "delivery";

      if (!farmerId) {
        return res.status(400).json({ success: false, error: "Missing farmerId." });
      }
      if (delivery !== "delivery") {
        return res.json({
          success: true,
          deliveryFee: 0,
          distanceKm: 0,
          tier: null,
          total: null,
        });
      }
      if (!address || !address.city || !address.barangay) {
        return res.status(400).json({
          success: false,
          error: "Pick a delivery City and Barangay first.",
        });
      }

      const farmerSnap = await db.collection("users").doc(farmerId).get();
      if (!farmerSnap.exists) {
        return res.status(404).json({ success: false, error: "Farm not found." });
      }
      const { farmLocationFromProfile, buyerLocationFromAddress, quoteDeliveryFee } =
        require("./deliveryFee");
      const farm = farmLocationFromProfile(farmerSnap.data() || {});
      const buyer = buyerLocationFromAddress(address);

      if (!String(farm.city || "").trim() || !String(farm.barangay || "").trim()) {
        return res.status(400).json({
          success: false,
          code: "FARM_MISSING_BARANGAY",
          error:
            "This farm has no barangay set yet. Ask the farmer to pick their City and Barangay in Farm Profile before delivery.",
        });
      }

      try {
        const q = quoteDeliveryFee(farm, buyer);
        return res.json({
          success: true,
          deliveryFee: q.fee,
          distanceKm: q.distanceKm,
          tier: q.tier,
        });
      } catch (e) {
        return res.status(400).json({
          success: false,
          error: e.message,
          ...(e?.code ? { code: e.code } : {}),
        });
      }
    } catch (error) {
      console.error("DELIVERY QUOTE ERROR:", error);
      return res.status(error.status || 400).json({
        success: false,
        error: error.message || "Unable to quote delivery.",
      });
    }
  });

  // ------------------------------------------------------------
  // DECLINE ORDER (farmer, pending only, never a paid order)
  // ------------------------------------------------------------
  router.post("/orders/:orderId/decline", async (req, res) => {
    try {
      const decoded = await getAuthUser(req, auth);

      const orderRef = db.collection("orders").doc(String(req.params.orderId));
      const reason = String(req.body?.reason || "Declined by farmer.").trim();

      await db.runTransaction(async (transaction) => {
        const orderSnap = await transaction.get(orderRef);

        if (!orderSnap.exists) throw new Error("Order not found.");

        const order = orderSnap.data() || {};

        if (order.farmerId !== decoded.uid) {
          throw new Error("You are not authorized to decline this order.");
        }

        if (order.status !== "pending") {
          throw new Error("Only pending orders can be declined.");
        }

        if (order.paymentStatus === "paid") {
          throw new Error(
            "This order has already been paid and cannot be declined here because a refund is required."
          );
        }

        const now = new Date();

        transaction.update(orderRef, {
          status: "cancelled",
          farmerDecision: "rejected",
          farmerDecisionAt: now,
          cancelledBy: "farmer",
          cancelReason: reason,
          rejectionReason: reason,
          cancelledAt: now,
          paymentStatus:
            order.payment === "gcash"
              ? "cancelled"
              : order.paymentStatus || "pending",
          inventoryFulfilled: false,
          fulfillmentStatus: "pending",
          updatedAt: now,
        });
      });

      return res.json({ success: true });
    } catch (error) {
      console.error("DECLINE ORDER ERROR:", error);

      return res.status(400).json({ success: false, error: error.message });
    }
  });

  // ------------------------------------------------------------
  // CANCEL ORDER
  // Buyer: pending / accepted (unpaid).  Farmer: pending / accepted.
  // No cancellation after processing. Paid GCash needs a refund flow.
  // An accepted COD order already had its stock deducted, so cancelling
  // it also RESTORES the stock and releases the held commission.
  // ------------------------------------------------------------
  router.post("/orders/:orderId/cancel", async (req, res) => {
    try {
      const decoded = await getAuthUser(req, auth);

      const orderRef = db.collection("orders").doc(String(req.params.orderId));
      const reason = String(req.body?.reason || "Cancelled by user.").trim();

      const result = await db.runTransaction(async (transaction) => {
        // ---------- READS ----------
        const orderSnap = await transaction.get(orderRef);

        if (!orderSnap.exists) throw new Error("Order not found.");

        const order = orderSnap.data() || {};

        const isBuyer = order.buyerId === decoded.uid;
        const isFarmer = order.farmerId === decoded.uid;

        if (!isBuyer && !isFarmer) {
          throw new Error("You are not authorized to cancel this order.");
        }

        if (order.status !== "pending" && order.status !== "accepted") {
          throw new Error(
            "This order can no longer be cancelled because it is already processing."
          );
        }

        if (order.payment === "gcash" && order.paymentStatus === "paid") {
          throw new Error(
            "This GCash order has already been paid and cannot be cancelled here because a refund is required."
          );
        }

        const isAcceptedCod =
          order.payment === "cod" && order.status === "accepted";

        // Only an accepted COD order may be cancelled after stock was deducted.
        if (order.inventoryFulfilled === true && !isAcceptedCod) {
          throw new Error(
            "This order can no longer be cancelled because inventory has already been fulfilled."
          );
        }

        const now = new Date();

        let wallet = null;
        let walletRef = null;
        let releasedReserve = 0;

        if (
          isAcceptedCod &&
          order.codCommissionReservationStatus === "reserved"
        ) {
          const farmerId = String(order.farmerId);

          walletRef = db.collection("farmerWallets").doc(farmerId);

          const walletSnap = await transaction.get(walletRef);

          wallet = sanitizeWallet(
            farmerId,
            walletSnap.exists ? walletSnap.data() : {}
          );

          releasedReserve = roundMoney(order.codCommissionReserved);
        }

        let restockPlan = null;

        if (isAcceptedCod && order.inventoryFulfilled === true) {
          restockPlan = await planRestock(transaction, order);
        }

        // ---------- WRITES ----------
        if (restockPlan) {
          applyRestock(transaction, restockPlan);
        }

        if (wallet && releasedReserve > 0) {
          const nextReserve = roundMoney(
            wallet.commissionReserveBalance + releasedReserve
          );
          const nextHeld = Math.max(
            0,
            roundMoney(wallet.commissionReserveHeld - releasedReserve)
          );

          transaction.set(
            walletRef,
            {
              ...wallet,
              commissionReserveBalance: nextReserve,
              commissionReserveHeld: nextHeld,
              updatedAt: now,
            },
            { merge: true }
          );

          transaction.set(db.collection("walletTransactions").doc(), {
            farmerId: String(order.farmerId),
            type: "cod_commission_reservation_released",
            direction: "credit",
            amount: releasedReserve,
            balanceAfter: wallet.availableBalance,
            commissionReserveAfter: nextReserve,
            commissionReserveHeldAfter: nextHeld,
            orderId: orderSnap.id,
            orderNumber: order.orderNumber || null,
            status: "completed",
            description: `Released COD commission reserve because ${order.orderNumber || orderSnap.id} was cancelled.`,
            createdAt: now,
            completedAt: now,
          });
        }

        transaction.update(orderRef, {
          status: "cancelled",
          cancelledBy: isFarmer ? "farmer" : "buyer",
          cancelReason: reason,
          cancelledAt: now,
          paymentStatus:
            order.payment === "gcash"
              ? "cancelled"
              : order.paymentStatus || "pending",

          inventoryFulfilled: false,
          fulfillmentStatus: "pending",
          ...(restockPlan
            ? {
                inventoryRestoredAt: now,
                // True only if some product had no batch trace to restore.
                restockNeedsManualReview: restockPlan.skipped === true,
              }
            : {}),

          codCommissionReservationStatus:
            releasedReserve > 0
              ? "released"
              : order.codCommissionReservationStatus || "not_applicable",
          codCommissionReserved: 0,
          updatedAt: now,
        });

        return {
          orderId: orderSnap.id,
          cancelled: true,
          releasedCommissionReserve: releasedReserve,
          stockRestored: !!restockPlan,
        };
      });

      return res.json({ success: true, ...result });
    } catch (error) {
      console.error("CANCEL ORDER ERROR:", error);

      return res.status(400).json({ success: false, error: error.message });
    }
  });

  // ------------------------------------------------------------
  // RELEASE ORPHANED COD RESERVE
  // Only for CANCELLED orders that somehow still hold a reserve.
  // (Cancel already releases it; this is a safety net.)
  // ------------------------------------------------------------
  router.post("/orders/:orderId/release-cod-reserve", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);

      const orderRef = db.collection("orders").doc(String(req.params.orderId));
      const walletRef = db.collection("farmerWallets").doc(decoded.uid);

      const result = await db.runTransaction(async (transaction) => {
        const [orderSnap, walletSnap] = await Promise.all([
          transaction.get(orderRef),
          transaction.get(walletRef),
        ]);

        if (!orderSnap.exists) throw new Error("Order not found.");

        const order = orderSnap.data() || {};

        if (order.farmerId !== decoded.uid) {
          throw new Error("Unauthorized order.");
        }

        const amount = roundMoney(order.codCommissionReserved);

        if (
          order.status !== "cancelled" ||
          order.payment !== "cod" ||
          amount <= 0 ||
          order.codCommissionReservationStatus !== "reserved"
        ) {
          return { released: false, amount: 0 };
        }

        const wallet = sanitizeWallet(
          decoded.uid,
          walletSnap.exists ? walletSnap.data() : {}
        );

        const now = new Date();

        const nextReserve = roundMoney(wallet.commissionReserveBalance + amount);
        const nextHeld = Math.max(
          0,
          roundMoney(wallet.commissionReserveHeld - amount)
        );

        transaction.set(
          walletRef,
          {
            ...wallet,
            commissionReserveBalance: nextReserve,
            commissionReserveHeld: nextHeld,
            updatedAt: now,
          },
          { merge: true }
        );

        transaction.set(db.collection("walletTransactions").doc(), {
          farmerId: decoded.uid,
          type: "cod_commission_reservation_released",
          direction: "credit",
          amount,
          balanceAfter: wallet.availableBalance,
          commissionReserveAfter: nextReserve,
          commissionReserveHeldAfter: nextHeld,
          orderId: orderSnap.id,
          orderNumber: order.orderNumber || null,
          status: "completed",
          description: `Released reserved COD commission for ${order.orderNumber || orderSnap.id}.`,
          createdAt: now,
          completedAt: now,
        });

        transaction.update(orderRef, {
          codCommissionReservationStatus: "released",
          codCommissionReserved: 0,
          updatedAt: now,
        });

        return { released: true, amount };
      });

      return res.json({ success: true, ...result });
    } catch (error) {
      console.error("RELEASE COD RESERVE ERROR:", error);

      return res.status(400).json({ success: false, error: error.message });
    }
  });

  // ------------------------------------------------------------
  // WITHDRAW
  // request  -> reserved += amount (available unchanged)
  // ------------------------------------------------------------
  router.post("/withdraw", async (req, res) => {
    try {
      const { decoded, user } = await requireFarmer(req, auth, db);
      const uid = decoded.uid;

      const payoutAccountRef = db.collection("farmerPayoutAccounts").doc(uid);
      const walletRef = db.collection("farmerWallets").doc(uid);

      const payoutAccountSnap = await payoutAccountRef.get();

      if (!payoutAccountSnap.exists) {
        return res.status(400).json({
          success: false,
          error: "Please add your GCash payout account first.",
        });
      }

      const payoutAccount = payoutAccountSnap.data() || {};

      // Throws (400) if the stored number is invalid.
      normalizeGcashNumber(payoutAccount.accountNumber);

      const hasRequestedAmount =
        req.body?.amount !== undefined && req.body?.amount !== null;

      const requestedAmount = hasRequestedAmount
        ? normalizeAmount(req.body.amount)
        : null;

      if (
        hasRequestedAmount &&
        (!Number.isFinite(requestedAmount) || requestedAmount <= 0)
      ) {
        return res
          .status(400)
          .json({ success: false, error: "Enter a valid withdrawal amount." });
      }

      const minimumWithdrawal = getMinimumWithdrawal();

      const withdrawalRef = db.collection("farmerWithdrawals").doc();
      const withdrawalId = withdrawalRef.id;
      const idempotencyKey = createIdempotencyKey("FG-WD");
      const referenceId = `FG-WD-${withdrawalId}`;
      const now = new Date();

      // ---------- 1. HOLD THE FUNDS (atomic) ----------
      const { amount, walletAfter } = await db.runTransaction(
        async (transaction) => {
          const walletSnap = await transaction.get(walletRef);

          const wallet = sanitizeWallet(
            uid,
            walletSnap.exists ? walletSnap.data() : {}
          );

          const withdrawable = getWithdrawableAmount(wallet);
          const amt = requestedAmount === null ? withdrawable : requestedAmount;

          if (!Number.isFinite(amt) || amt <= 0) {
            throw httpError(400, "No withdrawable balance is available.");
          }

          if (amt < minimumWithdrawal) {
            throw httpError(
              400,
              `Minimum withdrawal is ₱${minimumWithdrawal.toFixed(2)}.`
            );
          }

          if (amt > withdrawable + 0.001) {
            throw httpError(
              400,
              `Maximum withdrawable amount is ₱${withdrawable.toFixed(2)}.`,
              { withdrawableAmount: withdrawable }
            );
          }

          const walletTxnRef = db.collection("walletTransactions").doc();

          const nextWallet = {
            ...wallet,
            reservedBalance: roundMoney(wallet.reservedBalance + amt),
            updatedAt: now,
          };

          transaction.set(walletRef, nextWallet, { merge: true });

          transaction.set(walletTxnRef, {
            farmerId: uid,
            type: "withdrawal",
            direction: "debit",
            amount: amt,
            balanceAfter: wallet.availableBalance,
            commissionReserveAfter: wallet.commissionReserveBalance,
            commissionReserveHeldAfter: wallet.commissionReserveHeld,
            withdrawalId,
            status: "pending",
            description: "GCash withdrawal submitted to Xendit.",
            createdAt: now,
          });

          transaction.set(withdrawalRef, {
            farmerId: uid,
            amount: amt,
            minimumReserve: 0,
            payoutFee: 0,
            netAmount: amt,
            payoutMethod: "gcash",
            accountName: payoutAccount.accountName,
            postalCode: payoutAccount.postalCode || "",
            accountNumberMasked: payoutAccount.accountNumberMasked,
            status: "pending",
            idempotencyKey,
            xenditReferenceId: referenceId,
            walletTransactionId: walletTxnRef.id,
            requestedAt: now,
            updatedAt: now,
          });

          return { amount: amt, walletAfter: nextWallet };
        }
      );

      const buildWithdrawal = (status, extra = {}) => ({
        id: withdrawalId,
        farmerId: uid,
        amount,
        minimumReserve: 0,
        commissionReserveBalance: walletAfter.commissionReserveBalance,
        commissionReserveHeld: walletAfter.commissionReserveHeld,
        payoutFee: 0,
        netAmount: amount,
        payoutMethod: "gcash",
        accountName: payoutAccount.accountName,
        postalCode: payoutAccount.postalCode || "",
        accountNumberMasked: payoutAccount.accountNumberMasked,
        status,
        idempotencyKey,
        xenditReferenceId: referenceId,
        requestedAt: now,
        ...extra,
      });

      const withdrawableAfter = getWithdrawableAmount(walletAfter);

      // ---------- 2. SEND THE PAYOUT ----------
      let payout;

      try {
        payout = await payoutRequest({
          idempotencyKey,
          referenceId,
          accountName: payoutAccount.accountName,
          accountNumber: payoutAccount.accountNumber,
          amount,
          user: {
            ...user,
            farmerId: uid,
            payoutPostalCode: payoutAccount.postalCode || "",
          },
        });
      } catch (payoutError) {
        // ---- Ambiguous: the payout may exist. NEVER release the hold. ----
        if (payoutError.ambiguous) {
          await db.runTransaction(async (transaction) => {
            const fresh = await transaction.get(withdrawalRef);

            if (fresh.exists && (fresh.data() || {}).status === "pending") {
              transaction.set(
                withdrawalRef,
                {
                  status: "pending_review",
                  failureReason:
                    "Could not confirm the payout with Xendit. Funds stay held until it is resolved.",
                  updatedAt: new Date(),
                },
                { merge: true }
              );
            }
          });

          console.error("WITHDRAWAL NEEDS REVIEW:", {
            withdrawalId,
            referenceId,
            message: payoutError.message,
          });

          return res.status(202).json({
            success: true,
            withdrawal: buildWithdrawal("pending_review"),
            withdrawableAmount: withdrawableAfter,
          });
        }

        // ---- Definite failure: release the hold (only if still pending). ----
        await db.runTransaction(async (transaction) => {
          const [freshWithdrawalSnap, freshWalletSnap] = await Promise.all([
            transaction.get(withdrawalRef),
            transaction.get(walletRef),
          ]);

          if (
            !freshWithdrawalSnap.exists ||
            (freshWithdrawalSnap.data() || {}).status !== "pending"
          ) {
            return;
          }

          const freshWallet = sanitizeWallet(
            uid,
            freshWalletSnap.exists ? freshWalletSnap.data() : {}
          );

          const failedAt = new Date();

          transaction.set(
            walletRef,
            {
              ...freshWallet,
              reservedBalance: Math.max(
                0,
                roundMoney(freshWallet.reservedBalance - amount)
              ),
              updatedAt: failedAt,
            },
            { merge: true }
          );

          const walletTransactionId = (freshWithdrawalSnap.data() || {})
            .walletTransactionId;

          if (walletTransactionId) {
            transaction.set(
              db.collection("walletTransactions").doc(walletTransactionId),
              {
                status: "failed",
                completedAt: failedAt,
                description: "GCash withdrawal failed; held amount released.",
              },
              { merge: true }
            );
          }

          transaction.set(
            withdrawalRef,
            {
              status: "failed",
              failureCode: payoutError?.response?.error_code || null,
              failureReason:
                payoutError?.message || "Xendit payout request failed.",
              failedAt,
              updatedAt: failedAt,
            },
            { merge: true }
          );
        });

        throw payoutError;
      }

      // ---------- 3. MARK PROCESSING (never overwrite a webhook result) ----------
      const finalStatus = await db.runTransaction(async (transaction) => {
        const fresh = await transaction.get(withdrawalRef);
        const current = fresh.exists ? fresh.data() || {} : {};

        if (current.status !== "pending" && current.status !== "pending_review") {
          return current.status || "processing";
        }

        transaction.set(
          withdrawalRef,
          {
            status: "processing",
            processingAt: new Date(),
            xenditPayoutId: payout?.payout_id || payout?.id || null,
            xenditReferenceId: payout?.reference_id || referenceId,
            xenditStatus: payout?.status || "PENDING",
            updatedAt: new Date(),
          },
          { merge: true }
        );

        return "processing";
      });

      return res.json({
        success: true,
        withdrawal: buildWithdrawal(finalStatus, {
          xenditPayoutId: payout?.payout_id || payout?.id || null,
          xenditReferenceId: payout?.reference_id || referenceId,
          processingAt: new Date(),
        }),
        withdrawableAmount: withdrawableAfter,
      });
    } catch (error) {
      console.error("FARMER WITHDRAW ERROR:", error);

      return res.status(error.status || 400).json({
        success: false,
        error: error.message || "Unable to process withdrawal.",
        // Xendit validation details (which fields failed), so the app
        // can show more than a generic message.
        details: error.response || null,
        ...(error.withdrawableAmount !== undefined
          ? { withdrawableAmount: error.withdrawableAmount }
          : {}),
      });
    }
  });

  // ------------------------------------------------------------
  // DELIVER ORDER / FINANCIAL SETTLEMENT (idempotent)
  //
  // GCash: farmer earning (subtotal - commission) -> available balance.
  // COD  : commission is taken from the HELD reserve. COD product money
  //        is never credited to the wallet.
  // ------------------------------------------------------------
  router.post("/orders/:orderId/deliver", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);

      const orderId = String(req.params.orderId);
      const orderRef = db.collection("orders").doc(orderId);
      const walletRef = db.collection("farmerWallets").doc(decoded.uid);
      const adminWalletRef = db.collection("adminWallets").doc(ADMIN_WALLET_ID);

      let settlementResult = null;

      await db.runTransaction(async (transaction) => {
        const [orderSnap, walletSnap, adminWalletSnap] = await Promise.all([
          transaction.get(orderRef),
          transaction.get(walletRef),
          transaction.get(adminWalletRef),
        ]);

        if (!orderSnap.exists) throw new Error("Order not found.");

        const order = orderSnap.data() || {};

        if (order.farmerId !== decoded.uid) {
          throw new Error("You are not authorized to deliver this order.");
        }

        if (order.financialStatus === "settled") {
          settlementResult = {
            alreadySettled: true,
            farmerEarning: roundMoney(order.farmerEarning),
            commissionAmount: roundMoney(order.commissionAmount),
          };
          return;
        }

        if (order.status !== "to_receive" && order.status !== "delivered") {
          throw new Error("Only To Receive orders can be marked as delivered.");
        }

        if (order.payment !== "gcash" && order.payment !== "cod") {
          throw new Error("Order has an invalid payment method.");
        }

        if (order.inventoryFulfilled !== true) {
          throw new Error(
            "Inventory has not been fulfilled for this order yet."
          );
        }

        const wallet = sanitizeWallet(
          decoded.uid,
          walletSnap.exists ? walletSnap.data() : {}
        );

        const now = new Date();
        const rate = getCommissionRate();
        const subtotal = getOrderSubtotal(order);

        let nextAvailable = wallet.availableBalance;
        let nextReserve = wallet.commissionReserveBalance;
        let nextHeld = wallet.commissionReserveHeld;
        let commissionAmount;
        let farmerEarning = 0;

        if (order.payment === "gcash") {
          if (order.paymentStatus !== "paid") {
            throw new Error("This GCash order has not been paid.");
          }

          commissionAmount = roundMoney(subtotal * rate);
          farmerEarning = roundMoney(Math.max(0, subtotal - commissionAmount));
          nextAvailable = roundMoney(wallet.availableBalance + farmerEarning);
        } else {
          const reservedAmount = roundMoney(order.codCommissionReserved);

          const hasReservation =
            order.codCommissionReservationStatus === "reserved" &&
            reservedAmount > 0;

          if (hasReservation) {
            // The commission is exactly what was reserved at acceptance.
            // The order itself is the source of truth, so a short or
            // corrupted held-pool never blocks (or double-charges) delivery.
            commissionAmount = reservedAmount;

            if (wallet.commissionReserveHeld + 0.001 < reservedAmount) {
              console.warn(
                "COD held reserve is lower than the order reservation (self-healing).",
                {
                  orderId,
                  held: wallet.commissionReserveHeld,
                  reservedAmount,
                }
              );
            }

            nextHeld = Math.max(
              0,
              roundMoney(wallet.commissionReserveHeld - reservedAmount)
            );
          } else {
            // Legacy order accepted before reservations existed (or already
            // released): charge the commission now from the free reserve.
            const due = roundMoney(subtotal * rate);

            if (wallet.commissionReserveBalance + 0.001 < due) {
              throw new Error(
                `Insufficient commission reserve to settle this COD order. Required: ₱${due.toFixed(2)}. Available: ₱${wallet.commissionReserveBalance.toFixed(2)}. Please deposit to your commission reserve, then mark the order as delivered again.`
              );
            }

            commissionAmount = due;

            nextReserve = roundMoney(wallet.commissionReserveBalance - due);
          }
        }

        const isGcash = order.payment === "gcash";

        transaction.set(
          walletRef,
          {
            ...wallet,
            availableBalance: nextAvailable,
            commissionReserveBalance: nextReserve,
            commissionReserveHeld: nextHeld,
            totalEarned: isGcash
              ? roundMoney(wallet.totalEarned + farmerEarning)
              : wallet.totalEarned,
            totalGcashEarnings: isGcash
              ? roundMoney(wallet.totalGcashEarnings + farmerEarning)
              : wallet.totalGcashEarnings,
            totalCodCommissionPaid: !isGcash
              ? roundMoney(wallet.totalCodCommissionPaid + commissionAmount)
              : wallet.totalCodCommissionPaid,
            updatedAt: now,
          },
          { merge: true }
        );

        transaction.set(db.collection("walletTransactions").doc(), {
          farmerId: decoded.uid,
          type: isGcash ? "gcash_commission" : "cod_commission_debit",
          direction: isGcash ? "memo" : "debit",
          amount: commissionAmount,
          balanceAfter: nextAvailable,
          commissionReserveAfter: nextReserve,
          commissionReserveHeldAfter: nextHeld,
          orderId,
          orderNumber: order.orderNumber || null,
          status: "completed",
          description: isGcash
            ? `FarmGate commission recorded from GCash order ${order.orderNumber || orderId}.`
            : `COD commission collected from the farmer's commission reserve for ${order.orderNumber || orderId}.`,
          createdAt: now,
          completedAt: now,
        });

        if (isGcash && farmerEarning > 0) {
          transaction.set(db.collection("walletTransactions").doc(), {
            farmerId: decoded.uid,
            type: "gcash_earning",
            direction: "credit",
            amount: farmerEarning,
            balanceAfter: nextAvailable,
            commissionReserveAfter: nextReserve,
            commissionReserveHeldAfter: nextHeld,
            orderId,
            orderNumber: order.orderNumber || null,
            status: "completed",
            description: `Farmer earning from GCash order ${order.orderNumber || orderId}.`,
            createdAt: now,
            completedAt: now,
          });
        }

        transaction.set(db.collection("farmgateTransactions").doc(), {
          type: "commission",
          orderId,
          farmerId: decoded.uid,
          amount: commissionAmount,
          direction: "income",
          status: "completed",
          description: `FarmGate commission from order ${order.orderNumber || orderId}.`,
          createdAt: now,
          completedAt: now,
        });

        // Every delivered order credits its commission to the shared
        // admin wallet (idempotent: settled orders return early above).
        const adminWallet = sanitizeAdminWallet(
          adminWalletSnap.exists ? adminWalletSnap.data() : {}
        );
        const adminNextAvailable = roundMoney(
          adminWallet.availableBalance + commissionAmount
        );

        transaction.set(
          adminWalletRef,
          {
            ...adminWallet,
            availableBalance: adminNextAvailable,
            totalCommissionEarned: roundMoney(
              adminWallet.totalCommissionEarned + commissionAmount
            ),
            updatedAt: now,
          },
          { merge: true }
        );

        transaction.set(db.collection("walletTransactions").doc(), {
          farmerId: ADMIN_LEDGER_ID,
          type: "commission_credit",
          direction: "credit",
          amount: commissionAmount,
          balanceAfter: adminNextAvailable,
          orderId,
          orderNumber: order.orderNumber || null,
          reference: order.orderNumber || orderId,
          status: "completed",
          description: `Commission from order ${order.orderNumber || orderId}.`,
          createdAt: now,
          completedAt: now,
        });

        transaction.set(
          db.collection("farmgateFinancialSummary").doc("summary"),
          {
            totalCommission: FieldValue.increment(commissionAmount),
            totalFarmerEarnings: FieldValue.increment(farmerEarning),
            updatedAt: now,
          },
          { merge: true }
        );

        transaction.update(orderRef, {
          status: "delivered",
          deliveredAt: now,

          commissionRate: rate,
          commissionAmount,
          commissionStatus: "charged",
          commissionChargedAt: now,

          farmerEarning,
          farmerWalletCredited: isGcash,
          farmerWalletCreditedAt: isGcash ? now : null,

          financialStatus: "settled",

          codCommissionReservationStatus: isGcash
            ? "not_applicable"
            : "consumed",
          codCommissionReserved: 0,

          updatedAt: now,
        });

        settlementResult = {
          alreadySettled: false,
          farmerEarning,
          commissionAmount,
          commissionReserveBalance: nextReserve,
          commissionReserveHeld: nextHeld,
        };
      });

      return res.json({ success: true, ...settlementResult });
    } catch (error) {
      console.error("DELIVER ORDER / WALLET SETTLEMENT ERROR:", error);

      return res.status(400).json({ success: false, error: error.message });
    }
  });

  // ------------------------------------------------------------
  // ADMIN WALLET (single shared platform wallet)
  // ------------------------------------------------------------
  router.get("/admin/wallet", async (req, res) => {
    try {
      await requireAdmin(req, auth, db);

      const ref = db.collection("adminWallets").doc(ADMIN_WALLET_ID);
      const snap = await ref.get();

      const wallet = sanitizeAdminWallet(snap.exists ? snap.data() : {});

      if (!snap.exists) {
        await ref.set({ ...wallet, createdAt: new Date(), updatedAt: new Date() });
      }

      return res.json({
        success: true,
        wallet,
        withdrawableAmount: getAdminWithdrawableAmount(wallet),
        minimumWithdrawal: getMinimumWithdrawal(),
      });
    } catch (error) {
      console.error("GET ADMIN WALLET ERROR:", error);

      return sendWalletError(res, error, 500);
    }
  });

  // ------------------------------------------------------------
  // ADMIN TRANSACTIONS (latest 50, same ledger collection)
  // ------------------------------------------------------------
  router.get("/admin/transactions", async (req, res) => {
    try {
      await requireAdmin(req, auth, db);

      const transactions = await loadFarmerTransactions(ADMIN_LEDGER_ID);

      return res.json({ success: true, transactions });
    } catch (error) {
      console.error("GET ADMIN TRANSACTIONS ERROR:", error);

      return sendWalletError(res, error, 500);
    }
  });

  // ------------------------------------------------------------
  // ADMIN PAYOUT ACCOUNT
  // ------------------------------------------------------------
  router.get("/admin/payout-account", async (req, res) => {
    try {
      await requireAdmin(req, auth, db);

      const snap = await db
        .collection("adminPayoutAccounts")
        .doc(ADMIN_WALLET_ID)
        .get();

      if (!snap.exists) {
        return res.json({ success: true, payoutAccount: null });
      }

      const data = snap.data() || {};

      return res.json({
        success: true,
        payoutAccount: {
          accountName: data.accountName || "",
          postalCode: data.postalCode || "",
          city: data.city || "",
          province: data.province || "",
          street: data.street || "",
          accountNumberMasked: safeMaskGcashNumber(
            data.accountNumberMasked,
            data.accountNumber
          ),
          status: data.status || "active",
          createdAt: data.createdAt || null,
          updatedAt: data.updatedAt || null,
        },
      });
    } catch (error) {
      console.error("GET ADMIN PAYOUT ACCOUNT ERROR:", error);

      return sendWalletError(res, error, 500);
    }
  });

  router.put("/admin/payout-account", async (req, res) => {
    try {
      await requireAdmin(req, auth, db);

      const ref = db.collection("adminPayoutAccounts").doc(ADMIN_WALLET_ID);
      const existing = await ref.get();
      const existingData = existing.exists ? existing.data() || {} : {};

      const rawName =
        req.body?.accountName !== undefined
          ? String(req.body.accountName).trim()
          : existingData.accountName || "";
      const rawNumber =
        req.body?.accountNumber !== undefined &&
        String(req.body.accountNumber).trim() !== ""
          ? normalizeGcashNumber(req.body.accountNumber)
          : existingData.accountNumber || "";

      const pick = (key) =>
        req.body?.[key] !== undefined
          ? String(req.body[key]).trim()
          : existingData[key] || "";
      const postalCode = pick("postalCode");
      const city = pick("city");
      const province = pick("province");
      const street = pick("street");

      if (rawName.length < 3) {
        return res.status(400).json({
          success: false,
          error: "Enter the GCash account name.",
        });
      }

      if (rawNumber !== "") {
        normalizeGcashNumber(rawNumber);
      }

      if (postalCode !== "" && !/^\d{4}$/.test(postalCode)) {
        return res.status(400).json({
          success: false,
          error: "Enter a valid 4-digit Philippine postal code for payouts.",
        });
      }

      const now = new Date();
      const accountNumberMasked =
        rawNumber !== ""
          ? maskGcashNumber(rawNumber)
          : existingData.accountNumberMasked || "";

      await ref.set(
        {
          accountName: rawName,
          accountNumber: rawNumber,
          postalCode,
          city,
          province,
          street,
          accountNumberMasked,
          status: "active",
          createdAt: existing.exists ? existingData.createdAt || now : now,
          updatedAt: now,
        },
        { merge: true }
      );

      return res.json({
        success: true,
        payoutAccount: {
          accountName: rawName,
          postalCode,
          city,
          province,
          street,
          accountNumberMasked,
          status: "active",
          createdAt: existing.exists ? existingData.createdAt || now : now,
          updatedAt: now,
        },
      });
    } catch (error) {
      console.error("SAVE ADMIN PAYOUT ACCOUNT ERROR:", error);

      return sendWalletError(res, error, 400);
    }
  });

  // ------------------------------------------------------------
  // ADMIN WITHDRAW
  // request -> pendingWithdrawal += amount (available unchanged)
  // ------------------------------------------------------------
  router.post("/admin/withdraw", async (req, res) => {
    try {
      const { decoded: adminDecoded } = await requireAdmin(req, auth, db);

      const payoutAccountRef = db
        .collection("adminPayoutAccounts")
        .doc(ADMIN_WALLET_ID);
      const walletRef = db.collection("adminWallets").doc(ADMIN_WALLET_ID);

      const payoutAccountSnap = await payoutAccountRef.get();

      if (!payoutAccountSnap.exists) {
        return res.status(400).json({
          success: false,
          error: "Please save the admin GCash payout account first.",
        });
      }

      const payoutAccount = payoutAccountSnap.data() || {};

      normalizeGcashNumber(payoutAccount.accountNumber);

      const hasRequestedAmount =
        req.body?.amount !== undefined && req.body?.amount !== null;
      const requestedAmount = hasRequestedAmount
        ? normalizeAmount(req.body.amount)
        : null;

      if (
        hasRequestedAmount &&
        (!Number.isFinite(requestedAmount) || requestedAmount <= 0)
      ) {
        return res
          .status(400)
          .json({ success: false, error: "Enter a valid withdrawal amount." });
      }

      const minimumWithdrawal = getMinimumWithdrawal();
      const withdrawalRef = db.collection("adminWithdrawals").doc();
      const withdrawalId = withdrawalRef.id;
      const idempotencyKey = createIdempotencyKey("FG-ADM-WD");
      const referenceId = `FG-ADM-WD-${withdrawalId}`;
      const now = new Date();

      // ---------- 1. HOLD THE FUNDS (atomic) ----------
      const { amount, walletAfter } = await db.runTransaction(
        async (transaction) => {
          const walletSnap = await transaction.get(walletRef);
          const wallet = sanitizeAdminWallet(
            walletSnap.exists ? walletSnap.data() : {}
          );
          const withdrawable = getAdminWithdrawableAmount(wallet);
          const amt = requestedAmount === null ? withdrawable : requestedAmount;

          if (!Number.isFinite(amt) || amt <= 0) {
            throw httpError(400, "No withdrawable balance is available.");
          }

          if (amt < minimumWithdrawal) {
            throw httpError(
              400,
              `Minimum withdrawal is ₱${minimumWithdrawal.toFixed(2)}.`
            );
          }

          if (amt > withdrawable + 0.001) {
            throw httpError(
              400,
              `Maximum withdrawable amount is ₱${withdrawable.toFixed(2)}.`,
              { withdrawableAmount: withdrawable }
            );
          }

          const walletTxnRef = db.collection("walletTransactions").doc();
          const nextWallet = {
            ...wallet,
            pendingWithdrawal: roundMoney(wallet.pendingWithdrawal + amt),
            updatedAt: now,
          };

          transaction.set(walletRef, nextWallet, { merge: true });
          transaction.set(walletTxnRef, {
            farmerId: ADMIN_LEDGER_ID,
            type: "withdrawal",
            direction: "debit",
            amount: amt,
            balanceAfter: wallet.availableBalance,
            withdrawalId,
            reference: referenceId,
            status: "pending",
            description: "Admin GCash withdrawal submitted to Xendit.",
            createdAt: now,
          });
          transaction.set(withdrawalRef, {
            amount: amt,
            payoutFee: 0,
            netAmount: amt,
            payoutMethod: "gcash",
            accountName: payoutAccount.accountName,
            accountNumberMasked:
              payoutAccount.accountNumberMasked ||
              safeMaskGcashNumber(null, payoutAccount.accountNumber),
            status: "pending",
            idempotencyKey,
            xenditReferenceId: referenceId,
            walletTransactionId: walletTxnRef.id,
            requestedAt: now,
            updatedAt: now,
          });

          return { amount: amt, walletAfter: nextWallet };
        }
      );

      const buildWithdrawal = (status, extra = {}) => ({
        id: withdrawalId,
        amount,
        payoutFee: 0,
        netAmount: amount,
        payoutMethod: "gcash",
        accountName: payoutAccount.accountName,
        accountNumberMasked:
          payoutAccount.accountNumberMasked ||
          safeMaskGcashNumber(null, payoutAccount.accountNumber),
        status,
        idempotencyKey,
        xenditReferenceId: referenceId,
        requestedAt: now,
        ...extra,
      });

      const withdrawableAfter = getAdminWithdrawableAmount(walletAfter);

      // ---------- 2. SEND THE PAYOUT ----------
      // Address for Xendit falls back to the admin profile (the payout
      // form only collects name + number, like the farmer wallet).
      const [adminProfileSnap, adminUserSnap] = await Promise.all([
        db.collection("admins").doc(adminDecoded.uid).get(),
        db.collection("users").doc(adminDecoded.uid).get(),
      ]);
      const adminProfile = {
        ...(adminUserSnap.exists ? adminUserSnap.data() || {} : {}),
        ...(adminProfileSnap.exists ? adminProfileSnap.data() || {} : {}),
      };

      let payout;

      try {
        payout = await adminPayoutRequest({
          idempotencyKey,
          referenceId,
          payoutAccount,
          profile: adminProfile,
          amount,
        });
      } catch (payoutError) {
        if (payoutError.ambiguous) {
          await db.runTransaction(async (transaction) => {
            const fresh = await transaction.get(withdrawalRef);

            if (fresh.exists && (fresh.data() || {}).status === "pending") {
              transaction.set(
                withdrawalRef,
                {
                  status: "pending_review",
                  failureReason:
                    "Could not confirm the payout with Xendit. Funds stay held until it is resolved.",
                  updatedAt: new Date(),
                },
                { merge: true }
              );
            }
          });

          console.error("ADMIN WITHDRAWAL NEEDS REVIEW:", {
            withdrawalId,
            referenceId,
            message: payoutError.message,
          });

          return res.status(202).json({
            success: true,
            withdrawal: buildWithdrawal("pending_review"),
            withdrawableAmount: withdrawableAfter,
          });
        }

        await db.runTransaction(async (transaction) => {
          const [freshWithdrawalSnap, freshWalletSnap] = await Promise.all([
            transaction.get(withdrawalRef),
            transaction.get(walletRef),
          ]);

          if (
            !freshWithdrawalSnap.exists ||
            (freshWithdrawalSnap.data() || {}).status !== "pending"
          ) {
            return;
          }

          const freshWallet = sanitizeAdminWallet(
            freshWalletSnap.exists ? freshWalletSnap.data() : {}
          );
          const failedAt = new Date();

          transaction.set(
            walletRef,
            {
              ...freshWallet,
              pendingWithdrawal: Math.max(
                0,
                roundMoney(freshWallet.pendingWithdrawal - amount)
              ),
              updatedAt: failedAt,
            },
            { merge: true }
          );

          const walletTransactionId = (freshWithdrawalSnap.data() || {})
            .walletTransactionId;

          if (walletTransactionId) {
            transaction.set(
              db.collection("walletTransactions").doc(walletTransactionId),
              {
                status: "failed",
                completedAt: failedAt,
                description: "Admin GCash withdrawal failed; held amount released.",
              },
              { merge: true }
            );
          }

          transaction.set(
            withdrawalRef,
            {
              status: "failed",
              failureCode: payoutError?.response?.error_code || null,
              failureReason:
                payoutError?.message || "Xendit payout request failed.",
              failedAt,
              updatedAt: failedAt,
            },
            { merge: true }
          );
        });

        throw payoutError;
      }

      // ---------- 3. MARK PROCESSING (never overwrite a webhook result) ----------
      const finalStatus = await db.runTransaction(async (transaction) => {
        const fresh = await transaction.get(withdrawalRef);
        const current = fresh.exists ? fresh.data() || {} : {};

        if (current.status !== "pending" && current.status !== "pending_review") {
          return current.status || "processing";
        }

        transaction.set(
          withdrawalRef,
          {
            status: "processing",
            processingAt: new Date(),
            xenditPayoutId: payout?.payout_id || payout?.id || null,
            xenditReferenceId: payout?.reference_id || referenceId,
            xenditStatus: payout?.status || "PENDING",
            updatedAt: new Date(),
          },
          { merge: true }
        );

        return "processing";
      });

      return res.json({
        success: true,
        withdrawal: buildWithdrawal(finalStatus, {
          xenditPayoutId: payout?.payout_id || payout?.id || null,
          xenditReferenceId: payout?.reference_id || referenceId,
          processingAt: new Date(),
        }),
        withdrawableAmount: withdrawableAfter,
      });
    } catch (error) {
      console.error("ADMIN WITHDRAW ERROR:", error);

      return res.status(error.status || 400).json({
        success: false,
        error: error.message || "Unable to process withdrawal.",
        details: error.response || null,
        ...(error.withdrawableAmount !== undefined
          ? { withdrawableAmount: error.withdrawableAmount }
          : {}),
      });
    }
  });

  // ------------------------------------------------------------
  // ADMIN FINANCIAL SUMMARY
  // ------------------------------------------------------------
  router.get("/admin/financial-summary", async (req, res) => {
    try {
      const decoded = await getAuthUser(req, auth);

      const userSnap = await db.collection("users").doc(decoded.uid).get();

      if (!userSnap.exists || userSnap.data()?.role !== "admin") {
        return res.status(403).json({
          success: false,
          error: "Only admin accounts can view FarmGate financial summary.",
        });
      }

      const summarySnap = await db
        .collection("farmgateFinancialSummary")
        .doc("summary")
        .get();

      const summary = summarySnap.exists ? summarySnap.data() || {} : {};

      return res.json({
        success: true,
        summary: {
          totalCommission: roundMoney(summary.totalCommission),
          totalDeliveryFees: roundMoney(summary.totalDeliveryFees),
          totalFarmerEarnings: roundMoney(summary.totalFarmerEarnings),
          totalFarmerWithdrawals: roundMoney(summary.totalFarmerWithdrawals),
          totalFarmerCommissionDeposits: roundMoney(
            summary.totalFarmerCommissionDeposits
          ),
          updatedAt: summary.updatedAt || null,
        },
      });
    } catch (error) {
      console.error("GET FARMGATE FINANCIAL SUMMARY ERROR:", error);

      return res.status(500).json({
        success: false,
        error: error.message || "Failed to load FarmGate financial summary.",
      });
    }
  });

  // ------------------------------------------------------------
  // XENDIT PAYOUT WEBHOOK
  // ------------------------------------------------------------
  router.post("/webhook/xendit/payout", async (req, res) => {
    try {
      const expectedToken = getEnv("XENDIT_WEBHOOK_TOKEN");
      const callbackToken = req.headers["x-callback-token"];

      if (!expectedToken) {
        return res.status(500).json({
          success: false,
          error: "XENDIT_WEBHOOK_TOKEN is not configured.",
        });
      }

      if (!safeCompare(String(callbackToken || ""), expectedToken)) {
        return res.status(401).json({
          success: false,
          error: "Invalid payout webhook token.",
        });
      }

      const event = String(req.body?.event || "");
      const data = req.body?.data || {};

      const withdrawalDoc = await findWithdrawal({
        db,
        payoutId: data?.payout_id,
        referenceId: data?.reference_id,
      });

      if (withdrawalDoc) {
        await applyWithdrawalWebhook({ db, withdrawalDoc, data, event });

        return res.status(200).json({ success: true });
      }

      const adminWithdrawalDoc = await findAdminWithdrawal({
        db,
        payoutId: data?.payout_id,
        referenceId: data?.reference_id,
      });

      if (!adminWithdrawalDoc) {
        return res.status(200).json({
          success: true,
          message: "Webhook acknowledged. Withdrawal not found.",
        });
      }

      await applyAdminWithdrawalWebhook({
        db,
        withdrawalDoc: adminWithdrawalDoc,
        data,
        event,
      });

      return res.status(200).json({ success: true });
    } catch (error) {
      console.error("XENDIT PAYOUT WEBHOOK ERROR:", error);

      return res.status(500).json({
        success: false,
        error: error.message || "Payout webhook processing failed.",
      });
    }
  });

  return router;
};

module.exports = {
  createWalletRouter,
  handleCommissionDepositWebhook,
  getWithdrawableAmount,
  getCommissionRate,
  // Exported for unit tests (no logic change to /deliver settlement).
  _test: { priceOrderOnServer, getOrderSubtotal, roundMoney, sanitizeWallet },
};