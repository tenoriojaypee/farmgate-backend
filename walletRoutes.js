const express = require("express");
const crypto = require("crypto");
const { FieldValue } = require("firebase-admin/firestore");

const XENDIT_BASE_URL = "https://api.xendit.co";
const XENDIT_PAYMENT_API_VERSION = "2024-11-11";
const XENDIT_PAYOUT_API_VERSION = "2025-09-01";

const DEFAULT_COMMISSION_RATE = 0.03;
const DEFAULT_MIN_COMMISSION_DEPOSIT = 100;
const MAX_COMMISSION_DEPOSIT = 100000;

const roundMoney = (value) => Number(Number(value || 0).toFixed(2));

const normalizeAmount = (value) => {
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

const getMinimumCommissionDeposit = () =>
  normalizeAmount(
    getEnv("FARMER_COMMISSION_DEPOSIT_MINIMUM") ||
      DEFAULT_MIN_COMMISSION_DEPOSIT
  );

const createIdempotencyKey = (prefix) =>
  `${prefix}-${Date.now()}-${crypto.randomUUID()}`;

const normalizeGcashNumber = (value) => {
  const raw = String(value || "").trim();
  const digits = raw.replace(/\D/g, "");

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

const xenditRequest = async (path, options = {}) => {
  const secretKey = getEnv("XENDIT_SECRET_KEY");
  if (!secretKey) throw new Error("XENDIT_SECRET_KEY is not configured.");

  const response = await fetch(`${XENDIT_BASE_URL}${path}`, {
    ...options,
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
  const action = actions.find(
    (item) => item?.type === "REDIRECT_CUSTOMER"
  );
  return action?.value || action?.url || null;
};

const getAuthUser = async (req, auth) => {
  const authorization = req.headers.authorization;

  if (
    typeof authorization !== "string" ||
    !authorization.startsWith("Bearer ")
  ) {
    throw new Error("Missing Firebase authentication token.");
  }

  const token = authorization.substring("Bearer ".length);
  return await auth.verifyIdToken(token);
};

const requireFarmer = async (req, auth, db) => {
  const decoded = await getAuthUser(req, auth);
  const userSnap = await db.collection("users").doc(decoded.uid).get();

  if (!userSnap.exists) throw new Error("User profile not found.");

  const user = userSnap.data() || {};

  if (user.role !== "farmer") {
    throw new Error("Only farmer accounts can access this wallet.");
  }

  return { decoded, user };
};

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
  // Kept for backward compatibility with old wallet documents.
  // FarmGate no longer enforces a minimum earnings-wallet reserve.
  minimumReserve: 0,
  currency: "PHP",
});

const sanitizeWallet = (farmerId, data = {}) => ({
  ...walletDefaults(farmerId),
  ...data,
  farmerId,
  availableBalance: normalizeAmount(data.availableBalance),
  pendingBalance: normalizeAmount(data.pendingBalance),
  reservedBalance: normalizeAmount(data.reservedBalance),
  commissionReserveBalance: normalizeAmount(data.commissionReserveBalance),
  commissionReserveHeld: normalizeAmount(data.commissionReserveHeld),
  totalCommissionDeposited: normalizeAmount(data.totalCommissionDeposited),
  totalCodCommissionPaid: normalizeAmount(data.totalCodCommissionPaid),
  codCommissionDue: normalizeAmount(data.codCommissionDue),
  codDeliveryFeeDue: normalizeAmount(data.codDeliveryFeeDue),
  totalEarned: normalizeAmount(data.totalEarned),
  totalWithdrawn: normalizeAmount(data.totalWithdrawn),
  totalGcashEarnings: normalizeAmount(data.totalGcashEarnings),
  // Minimum wallet reserve is no longer enforced.
  minimumReserve: 0,
  currency: "PHP",
});

const getWithdrawableAmount = (wallet) =>
  Math.max(
    0,
    roundMoney(wallet.availableBalance) -
      roundMoney(wallet.reservedBalance) -
      roundMoney(wallet.codCommissionDue) -
      roundMoney(wallet.codDeliveryFeeDue)
  );

const getOrderSubtotal = (order) => {
  const savedSubtotal = normalizeAmount(order?.subTotal);
  if (Number.isFinite(savedSubtotal) && savedSubtotal >= 0) {
    return savedSubtotal;
  }

  return roundMoney(
    (Array.isArray(order?.products) ? order.products : []).reduce(
      (sum, item) => sum + Number(item?.price || 0) * Number(item?.quantity || 0),
      0
    )
  );
};

const getCodCommission = (order) => {
  const rate = getCommissionRate();
  return {
    rate,
    subtotal: getOrderSubtotal(order),
    amount: roundMoney(getOrderSubtotal(order) * rate),
  };
};

const getExpectedFarmerEarning = (order) => {
  const subtotal = getOrderSubtotal(order);
  const savedEarning = normalizeAmount(order?.farmerEarning);

  if (Number.isFinite(savedEarning) && savedEarning > 0) {
    return savedEarning;
  }

  const commission = roundMoney(subtotal * getCommissionRate());
  return roundMoney(Math.max(0, subtotal - commission));
};

const getPendingProductBalance = async (db, farmerId) => {
  const snapshot = await db
    .collection("orders")
    .where("farmerId", "==", farmerId)
    .get();

  const pendingStatuses = new Set([
    "accepted",
    "processing",
    "to_receive",
  ]);

  let total = 0;

  for (const docSnap of snapshot.docs) {
    const order = docSnap.data() || {};

    if (!pendingStatuses.has(String(order.status || ""))) {
      continue;
    }

    if (order.payment === "gcash" && order.paymentStatus !== "paid") {
      continue;
    }

    total += getExpectedFarmerEarning(order);
  }

  return roundMoney(total);
};

const getAvailableStockForOrder = async (db, products) => {
  for (const product of products || []) {
    const productId = String(product?.productId || "");
    const quantity = Number(product?.quantity || 0);

    if (!productId || !Number.isFinite(quantity) || quantity <= 0) {
      throw new Error("Order contains an invalid product or quantity.");
    }

    const snapshot = await db
      .collection("productBatches")
      .where("productId", "==", productId)
      .get();

    const available = snapshot.docs.reduce((sum, docSnap) => {
      const batch = docSnap.data() || {};
      const stock = Number(batch.stock || 0);

      if (
        batch.archived === true ||
        batch.status !== "Available" ||
        !Number.isFinite(stock) ||
        stock <= 0
      ) {
        return sum;
      }

      return sum + stock;
    }, 0);

    if (available < quantity) {
      throw new Error(
        `Insufficient stock for ${product.name || productId}. Available: ${available}, Requested: ${quantity}.`
      );
    }
  }
};

const payoutRequest = async ({
  idempotencyKey,
  referenceId,
  accountName,
  accountNumber,
  amount,
  user,
}) => {
  const secretKey = getEnv("XENDIT_PAYOUT_SECRET_KEY");
  if (!secretKey) throw new Error("XENDIT_PAYOUT_SECRET_KEY is not configured.");

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

  if (!payoutCity || !payoutProvince || !payoutStreet) {
    throw new Error(
      "Your farmer profile must have a complete address before a GCash payout can be sent."
    );
  }

  if (!/^\d{4}$/.test(postalCode)) {
    throw new Error(
      "Your GCash payout account must have a valid 4-digit postal code before a GCash payout can be sent."
    );
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
      address: {
        country: "PH",
        province_state: payoutProvince,
        city: payoutCity,
        street_line_1: payoutStreet,
        postal_code: postalCode,
      },
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

  const response = await fetch(`${XENDIT_BASE_URL}/v3/payouts`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${Buffer.from(`${secretKey}:`).toString("base64")}`,
      "Content-Type": "application/json",
      "api-version": XENDIT_PAYOUT_API_VERSION,
      "idempotency-key": idempotencyKey,
    },
    body: JSON.stringify(payload),
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
        `Xendit payout request failed with status ${response.status}.`
    );
    error.status = response.status;
    error.response = data;
    throw error;
  }

  return data;
};

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

  await db.runTransaction(async (transaction) => {
    const [withdrawalSnap, walletSnap] = await Promise.all([
      transaction.get(withdrawalRef),
      transaction.get(db.collection("farmerWallets").doc(farmerId)),
    ]);

    if (!withdrawalSnap.exists) return;

    const withdrawal = withdrawalSnap.data() || {};
    const walletRef = db.collection("farmerWallets").doc(farmerId);
    const wallet = sanitizeWallet(
      farmerId,
      walletSnap.exists ? walletSnap.data() : {}
    );

    const status = String(data?.status || "").toUpperCase();
    const currentStatus = String(withdrawal.status || "");

    const finalFailure =
      event === "v3_payout.failed" ||
      event === "v3_payout.rejected" ||
      status === "FAILED" ||
      status === "REJECTED";

    const reversed =
      event === "v3_payout.reversed" || status === "REVERSED";

    const succeeded =
      event === "v3_payout.succeeded" || status === "SUCCEEDED";

    if (currentStatus === "succeeded" && !reversed) return;
    if (["failed", "rejected", "reversed"].includes(currentStatus) && !reversed) {
      return;
    }

    if (reversed || finalFailure) {
      const nextReserved = Math.max(
        0,
        roundMoney(wallet.reservedBalance - amount)
      );
      const nextAvailable = reversed
        ? roundMoney(wallet.availableBalance + amount)
        : roundMoney(wallet.availableBalance);

      transaction.set(
        walletRef,
        {
          ...wallet,
          availableBalance: nextAvailable,
          reservedBalance: nextReserved,
          updatedAt: new Date(),
        },
        { merge: true }
      );

      const walletTransactionId = withdrawal.walletTransactionId;
      if (walletTransactionId) {
        transaction.set(
          db.collection("walletTransactions").doc(walletTransactionId),
          {
            status: "reversed",
            direction: "credit",
            balanceAfter: nextAvailable,
            completedAt: new Date(),
            description: `Farmer GCash withdrawal ${reversed ? "reversed" : "failed/rejected"}; reserved amount released.`,
          },
          { merge: true }
        );
      }

      transaction.set(
        withdrawalRef,
        {
          status: reversed ? "reversed" : status === "REJECTED" ? "rejected" : "failed",
          xenditPayoutId: data?.payout_id || withdrawal.xenditPayoutId || null,
          xenditReferenceId:
            data?.reference_id || withdrawal.xenditReferenceId || null,
          xenditStatus: data?.status || null,
          failureCode: data?.failure_code || null,
          failureReason: data?.failure_reason || null,
          updatedAt: new Date(),
          failedAt: new Date(),
          completedAt: reversed ? new Date() : null,
        },
        { merge: true }
      );

      if (reversed) {
        const reversalRef = db.collection("walletTransactions").doc();
        transaction.set(reversalRef, {
          farmerId,
          type: "withdrawal_reversal",
          direction: "credit",
          amount,
          balanceAfter: nextAvailable,
          commissionReserveBalanceAfter: wallet.commissionReserveBalance,
          commissionReserveHeldAfter: wallet.commissionReserveHeld,
          withdrawalId: withdrawalDoc.id,
          status: "completed",
          description: "Xendit reversed the farmer GCash payout; the amount was returned to the earnings balance.",
          createdAt: new Date(),
          completedAt: new Date(),
        });
      }

      return;
    }

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
          updatedAt: new Date(),
        },
        { merge: true }
      );

      transaction.set(
        withdrawalRef,
        {
          status: "succeeded",
          xenditPayoutId: data?.payout_id || withdrawal.xenditPayoutId || null,
          xenditReferenceId:
            data?.reference_id || withdrawal.xenditReferenceId || null,
          xenditStatus: data?.status || null,
          completedAt: new Date(),
          updatedAt: new Date(),
        },
        { merge: true }
      );

      if (withdrawal.walletTransactionId) {
        transaction.set(
          db.collection("walletTransactions").doc(withdrawal.walletTransactionId),
          {
            status: "completed",
            balanceAfter: nextAvailable,
            completedAt: new Date(),
            description: "Farmer GCash withdrawal completed.",
          },
          { merge: true }
        );
      }

      transaction.set(
        db.collection("farmgateFinancialSummary").doc("summary"),
        {
          totalFarmerWithdrawals: FieldValue.increment(amount),
          updatedAt: new Date(),
        },
        { merge: true }
      );

      return;
    }

    const nextStatus =
      event === "v3_payout.pending_compliance" ||
      status === "PENDING_COMPLIANCE_REVIEW"
        ? "pending_compliance"
        : "processing";

    transaction.set(
      withdrawalRef,
      {
        status: nextStatus,
        xenditPayoutId: data?.payout_id || withdrawal.xenditPayoutId || null,
        xenditReferenceId:
          data?.reference_id || withdrawal.xenditReferenceId || null,
        xenditStatus: data?.status || null,
        processingAt: withdrawal.processingAt || new Date(),
        updatedAt: new Date(),
      },
      { merge: true }
    );
  });
};

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
  const type = String(metadata.type || "");

  if (type !== "farmer_commission_deposit") {
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

  if (event === "payment.failure") {
    if (deposit.status === "completed") {
      return { handled: true, alreadyCompleted: true };
    }

    await depositRef.update({
      status: "failed",
      xenditPaymentId: data?.payment_id || deposit.xenditPaymentId || null,
      xenditPaymentRequestId:
        data?.payment_request_id || deposit.xenditPaymentRequestId || null,
      xenditReferenceId:
        data?.reference_id || deposit.xenditReferenceId || null,
      xenditPaymentStatus: data?.status || "FAILED",
      failureCode: data?.failure_code || data?.error_code || null,
      failureReason:
        data?.failure_reason || data?.failure_message || data?.message || null,
      failedAt: new Date(),
      updatedAt: new Date(),
    });

    return { handled: true, failed: true };
  }

  if (event !== "payment.capture" || data?.status !== "SUCCEEDED") {
    await depositRef.set(
      {
        xenditPaymentStatus: data?.status || null,
        xenditPaymentId: data?.payment_id || deposit.xenditPaymentId || null,
        xenditPaymentRequestId:
          data?.payment_request_id || deposit.xenditPaymentRequestId || null,
        xenditReferenceId:
          data?.reference_id || deposit.xenditReferenceId || null,
        updatedAt: new Date(),
      },
      { merge: true }
    );

    return { handled: true, acknowledged: true };
  }

  const capturedAmount = normalizeAmount(
    data?.captures?.find((capture) => capture?.status === "SUCCEEDED")
      ?.capture_amount ??
      data?.captures?.[0]?.capture_amount ??
      data?.request_amount
  );

  if (!Number.isFinite(capturedAmount) || capturedAmount < depositAmount) {
    await depositRef.update({
      status: "manual_review",
      xenditPaymentId: data?.payment_id || null,
      xenditPaymentRequestId: data?.payment_request_id || null,
      xenditReferenceId: data?.reference_id || null,
      xenditPaymentStatus: data?.status || "SUCCEEDED",
      paidAt: new Date(),
      fulfillmentError: "Commission deposit amount mismatch.",
      updatedAt: new Date(),
    });

    return { handled: true, manualReview: true };
  }

  await db.runTransaction(async (transaction) => {
    const [freshDepositSnap, walletSnap] = await Promise.all([
      transaction.get(depositRef),
      transaction.get(db.collection("farmerWallets").doc(farmerId)),
    ]);

    if (!freshDepositSnap.exists) {
      throw new Error("Commission deposit record no longer exists.");
    }

    const freshDeposit = freshDepositSnap.data() || {};

    if (freshDeposit.status === "completed") return;

    const walletRef = db.collection("farmerWallets").doc(farmerId);
    const wallet = sanitizeWallet(
      farmerId,
      walletSnap.exists ? walletSnap.data() : {}
    );

    const nextReserve = roundMoney(
      wallet.commissionReserveBalance + depositAmount
    );
    const nextTotalDeposited = roundMoney(
      wallet.totalCommissionDeposited + depositAmount
    );

    transaction.set(
      walletRef,
      {
        ...wallet,
        commissionReserveBalance: nextReserve,
        totalCommissionDeposited: nextTotalDeposited,
        updatedAt: new Date(),
      },
      { merge: true }
    );

    const walletTransactionRef = db
      .collection("walletTransactions")
      .doc();

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
      description: `Commission reserve deposit for FarmGate COD commissions.`,
      createdAt: new Date(),
      completedAt: new Date(),
    });

    transaction.set(
      depositRef,
      {
        status: "completed",
        xenditPaymentId: data?.payment_id || null,
        xenditPaymentRequestId: data?.payment_request_id || null,
        xenditReferenceId: data?.reference_id || null,
        xenditPaymentStatus: data?.status || "SUCCEEDED",
        paidAt: new Date(),
        walletTransactionId: walletTransactionRef.id,
        updatedAt: new Date(),
      },
      { merge: true }
    );

    transaction.set(
      db.collection("farmgateFinancialSummary").doc("summary"),
      {
        totalFarmerCommissionDeposits: FieldValue.increment(depositAmount),
        updatedAt: new Date(),
      },
      { merge: true }
    );
  });

  return { handled: true, completed: true };
};

const createWalletRouter = ({ db, auth }) => {
  const router = express.Router();

  router.get("/me", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);
      const farmerId = decoded.uid;
      const ref = db.collection("farmerWallets").doc(farmerId);
      const snap = await ref.get();
      const wallet = sanitizeWallet(farmerId, snap.exists ? snap.data() : {});
      const pendingBalance = await getPendingProductBalance(db, farmerId);
      const walletWithPending = {
        ...wallet,
        pendingBalance,
      };

      if (!snap.exists || Number(wallet.pendingBalance || 0) !== pendingBalance) {
        await ref.set(
          {
            ...walletWithPending,
            ...(snap.exists ? {} : { createdAt: new Date() }),
            updatedAt: new Date(),
          },
          { merge: true }
        );
      }

      return res.json({
        success: true,
        wallet: walletWithPending,
        withdrawableAmount: getWithdrawableAmount(walletWithPending),
        minimumCommissionDeposit: getMinimumCommissionDeposit(),
      });
    } catch (error) {
      console.error("GET FARMER WALLET ERROR:", error);
      return res.status(401).json({ success: false, error: error.message });
    }
  });

  router.get("/transactions", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);
      const snapshot = await db
        .collection("walletTransactions")
        .where("farmerId", "==", decoded.uid)
        .limit(200)
        .get();

      const transactions = snapshot.docs
        .map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }))
        .sort((a, b) => toMillis(b.createdAt) - toMillis(a.createdAt));

      return res.json({ success: true, transactions });
    } catch (error) {
      console.error("GET WALLET TRANSACTIONS ERROR:", error);
      return res.status(401).json({ success: false, error: error.message });
    }
  });

  router.get("/payout-account", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);
      const ref = db.collection("farmerPayoutAccounts").doc(decoded.uid);
      const snap = await ref.get();

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

  router.put("/payout-account", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);
      const accountName = String(req.body?.accountName || "").trim();
      const accountNumber = normalizeGcashNumber(req.body?.accountNumber);
      const userSnap = await db.collection("users").doc(decoded.uid).get();
      const user = userSnap.exists ? userSnap.data() || {} : {};
      const postalCode = String(req.body?.postalCode || user.postalCode || "").trim();

      if (accountName.length < 3) {
        return res.status(400).json({ success: false, error: "Enter the GCash account name." });
      }

      if (!/^\d{4}$/.test(postalCode)) {
        return res.status(400).json({
          success: false,
          error: "Enter a valid 4-digit Philippine postal code for payouts.",
        });
      }

      const ref = db.collection("farmerPayoutAccounts").doc(decoded.uid);
      const existing = await ref.get();
      const now = new Date();

      await ref.set(
        {
          farmerId: decoded.uid,
          method: "gcash",
          channel: "PH_GCASH",
          accountName,
          accountNumber,
          postalCode,
          accountNumberMasked: maskGcashNumber(accountNumber),
          status: "active",
          createdAt: existing.exists ? existing.data()?.createdAt || now : now,
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
          accountNumberMasked: maskGcashNumber(accountNumber),
          status: "active",
          createdAt: existing.exists ? existing.data()?.createdAt || now : now,
          updatedAt: now,
        },
      });
    } catch (error) {
      console.error("SAVE PAYOUT ACCOUNT ERROR:", error);
      return res.status(400).json({ success: false, error: error.message });
    }
  });

  router.post("/deposit", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);
      const amount = normalizeAmount(req.body?.amount);
      const minimumDeposit = getMinimumCommissionDeposit();

      if (!Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({ success: false, error: "Enter a valid deposit amount." });
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

      const depositRef = db.collection("farmerCommissionDeposits").doc();
      const depositId = depositRef.id;
      const referenceId = `FG-DEP-${depositId}-${Date.now()}`;
      const publicBaseUrl = String(process.env.PUBLIC_BASE_URL || "")
        .trim()
        .replace(/\/+$/, "");

      if (!publicBaseUrl) {
        return res.status(500).json({ success: false, error: "PUBLIC_BASE_URL is not configured." });
      }

      const successReturnUrl =
        `${publicBaseUrl}/payment/success?type=farmer_deposit&depositId=${encodeURIComponent(depositId)}`;
      const failureReturnUrl =
        `${publicBaseUrl}/payment/failure?type=farmer_deposit&depositId=${encodeURIComponent(depositId)}`;

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
      return res.status(error.status || 400).json({
        success: false,
        error: error.message || "Unable to create commission reserve deposit.",
        details: error.response || null,
      });
    }
  });

  router.get("/deposits/:depositId", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);
      const depositId = String(req.params.depositId || "").trim();

      if (!depositId) {
        return res.status(400).json({
          success: false,
          error: "Deposit ID is required.",
        });
      }

      const depositRef = db
        .collection("farmerCommissionDeposits")
        .doc(depositId);
      const depositSnap = await depositRef.get();

      if (!depositSnap.exists) {
        return res.status(404).json({
          success: false,
          error: "Commission deposit not found.",
        });
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
          amount: normalizeAmount(deposit.amount),
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

  router.get("/cod-eligibility/:orderId", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);
      const orderRef = db.collection("orders").doc(String(req.params.orderId));
      const orderSnap = await orderRef.get();

      if (!orderSnap.exists) {
        return res.status(404).json({ success: false, error: "Order not found." });
      }

      const order = orderSnap.data() || {};

      if (order.farmerId !== decoded.uid) {
        return res.status(403).json({ success: false, error: "You are not authorized to accept this order." });
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
      const wallet = sanitizeWallet(decoded.uid, walletSnap.exists ? walletSnap.data() : {});
      const eligible = wallet.commissionReserveBalance >= commission.amount;

      return res.json({
        success: true,
        eligible,
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

  router.post("/orders/:orderId/accept", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);
      const orderRef = db.collection("orders").doc(String(req.params.orderId));

      const result = await db.runTransaction(async (transaction) => {
        const [orderSnap, walletSnap] = await Promise.all([
          transaction.get(orderRef),
          transaction.get(db.collection("farmerWallets").doc(decoded.uid)),
        ]);

        if (!orderSnap.exists) throw new Error("Order not found.");

        const order = orderSnap.data() || {};
        if (order.farmerId !== decoded.uid) {
          throw new Error("You are not authorized to accept this order.");
        }
        if (order.status !== "pending") {
          throw new Error("Only pending orders can be accepted.");
        }

        const walletRef = db.collection("farmerWallets").doc(decoded.uid);
        const wallet = sanitizeWallet(
          decoded.uid,
          walletSnap.exists ? walletSnap.data() : {}
        );

        let nextWallet = wallet;
        let reservationAmount = 0;
        const now = new Date();

        if (order.payment === "cod") {
          await getAvailableStockForOrder(db, order.products || []);

          const commission = getCodCommission(order);
          reservationAmount = commission.amount;

          if (wallet.commissionReserveBalance < reservationAmount) {
            throw new Error(
              `Insufficient commission reserve. Required: ₱${reservationAmount.toFixed(2)}. Available: ₱${wallet.commissionReserveBalance.toFixed(2)}. Please deposit first.`
            );
          }

          nextWallet = {
            ...wallet,
            commissionReserveBalance: roundMoney(
              wallet.commissionReserveBalance - reservationAmount
            ),
            commissionReserveHeld: roundMoney(
              wallet.commissionReserveHeld + reservationAmount
            ),
            updatedAt: now,
          };

          transaction.set(walletRef, nextWallet, { merge: true });

          const reserveTxnRef = db.collection("walletTransactions").doc();
          transaction.set(reserveTxnRef, {
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
        }

        transaction.update(orderRef, {
          status: "accepted",
          farmerDecision: "accepted",
          farmerDecisionAt: now,
          paymentStatus: order.paymentStatus || "pending",
          inventoryFulfilled: false,
          fulfillmentStatus: "pending",
          commissionRate: order.payment === "cod" ? getCommissionRate() : order.commissionRate || getCommissionRate(),
          commissionAmount: order.payment === "cod" ? reservationAmount : roundMoney(getOrderSubtotal(order) * getCommissionRate()),
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
      return res.status(400).json({ success: false, error: error.message });
    }
  });

  router.post("/orders/:orderId/cancel", async (req, res) => {
    try {
      const decoded = await getAuthUser(req, auth);
      const orderRef = db.collection("orders").doc(String(req.params.orderId));
      const reason = String(req.body?.reason || "Cancelled by user.").trim();

      const result = await db.runTransaction(async (transaction) => {
        const orderSnap = await transaction.get(orderRef);

        if (!orderSnap.exists) {
          throw new Error("Order not found.");
        }

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

        if (order.inventoryFulfilled === true) {
          throw new Error(
            "This order can no longer be cancelled because inventory has already been fulfilled."
          );
        }

        const now = new Date();
        let releasedReserve = 0;

        if (
          order.payment === "cod" &&
          order.status === "accepted" &&
          order.codCommissionReservationStatus === "reserved"
        ) {
          const farmerId = String(order.farmerId);
          const walletRef = db.collection("farmerWallets").doc(farmerId);
          const walletSnap = await transaction.get(walletRef);
          const wallet = sanitizeWallet(
            farmerId,
            walletSnap.exists ? walletSnap.data() : {}
          );

          releasedReserve = roundMoney(order.codCommissionReserved);

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

          const walletTxnRef = db.collection("walletTransactions").doc();
          transaction.set(walletTxnRef, {
            farmerId,
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
        };
      });

      return res.json({ success: true, ...result });
    } catch (error) {
      console.error("CANCEL ORDER ERROR:", error);
      return res.status(400).json({ success: false, error: error.message });
    }
  });

  router.post("/orders/:orderId/release-cod-reserve", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);
      const orderRef = db.collection("orders").doc(String(req.params.orderId));

      const result = await db.runTransaction(async (transaction) => {
        const [orderSnap, walletSnap] = await Promise.all([
          transaction.get(orderRef),
          transaction.get(db.collection("farmerWallets").doc(decoded.uid)),
        ]);

        if (!orderSnap.exists) throw new Error("Order not found.");

        const order = orderSnap.data() || {};
        if (order.farmerId !== decoded.uid) throw new Error("Unauthorized order.");

        const amount = roundMoney(order.codCommissionReserved);
        if (
          order.payment !== "cod" ||
          amount <= 0 ||
          order.codCommissionReservationStatus !== "reserved"
        ) {
          return { released: false, amount: 0 };
        }

        const walletRef = db.collection("farmerWallets").doc(decoded.uid);
        const wallet = sanitizeWallet(
          decoded.uid,
          walletSnap.exists ? walletSnap.data() : {}
        );
        const now = new Date();

        const nextReserve = roundMoney(wallet.commissionReserveBalance + amount);
        const nextHeld = Math.max(0, roundMoney(wallet.commissionReserveHeld - amount));

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

        const txnRef = db.collection("walletTransactions").doc();
        transaction.set(txnRef, {
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

  router.post("/withdraw", async (req, res) => {
    try {
      const { decoded, user } = await requireFarmer(req, auth, db);
      const uid = decoded.uid;
      const payoutAccountRef = db.collection("farmerPayoutAccounts").doc(uid);
      const walletRef = db.collection("farmerWallets").doc(uid);

      const [payoutAccountSnap, walletSnap] = await Promise.all([
        payoutAccountRef.get(),
        walletRef.get(),
      ]);

      if (!payoutAccountSnap.exists) {
        return res.status(400).json({ success: false, error: "Please add your GCash payout account first." });
      }

      const payoutAccount = payoutAccountSnap.data() || {};
      const wallet = sanitizeWallet(uid, walletSnap.exists ? walletSnap.data() : {});
      const requestedAmount =
        req.body?.amount === undefined ? null : normalizeAmount(req.body.amount);
      const withdrawable = getWithdrawableAmount(wallet);
      const amount = requestedAmount === null ? withdrawable : requestedAmount;

      if (!Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({ success: false, error: "No withdrawable balance is available." });
      }

      if (amount > withdrawable) {
        return res.status(400).json({
          success: false,
          error: `Maximum withdrawable amount is ₱${withdrawable.toFixed(2)}.`,
          withdrawableAmount: withdrawable,
        });
      }

      const withdrawalRef = db.collection("farmerWithdrawals").doc();
      const withdrawalId = withdrawalRef.id;
      const idempotencyKey = createIdempotencyKey("FG-WD");
      const referenceId = `FG-WD-${withdrawalId}`;
      const now = new Date();

      const reserved = roundMoney(wallet.reservedBalance + amount);
      const availableAfterReserve = roundMoney(wallet.availableBalance - amount);

      await db.runTransaction(async (transaction) => {
        const freshWalletSnap = await transaction.get(walletRef);
        const freshWallet = sanitizeWallet(uid, freshWalletSnap.exists ? freshWalletSnap.data() : {});
        const freshWithdrawable = getWithdrawableAmount(freshWallet);

        if (amount > freshWithdrawable) {
          throw new Error(
            `Your wallet changed while processing the withdrawal. Maximum now: ₱${freshWithdrawable.toFixed(2)}.`
          );
        }

        transaction.set(
          walletRef,
          {
            ...freshWallet,
            reservedBalance: roundMoney(freshWallet.reservedBalance + amount),
            availableBalance: roundMoney(freshWallet.availableBalance - amount),
            updatedAt: now,
          },
          { merge: true }
        );

        const walletTxnRef = db.collection("walletTransactions").doc();
        transaction.set(walletTxnRef, {
          farmerId: uid,
          type: "withdrawal",
          direction: "debit",
          amount,
          balanceAfter: roundMoney(freshWallet.availableBalance - amount),
          commissionReserveAfter: freshWallet.commissionReserveBalance,
          commissionReserveHeldAfter: freshWallet.commissionReserveHeld,
          withdrawalId,
          status: "pending",
          description: "GCash withdrawal submitted to Xendit.",
          createdAt: now,
        });

        transaction.set(withdrawalRef, {
          farmerId: uid,
          amount,
          minimumReserve: 0,
          payoutFee: 0,
          netAmount: amount,
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
      });

      try {
        const payout = await payoutRequest({
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

        await withdrawalRef.update({
          status: "processing",
          processingAt: new Date(),
          xenditPayoutId: payout?.payout_id || payout?.id || null,
          xenditReferenceId: payout?.reference_id || referenceId,
          xenditStatus: payout?.status || "PENDING",
          updatedAt: new Date(),
        });

        return res.json({
          success: true,
          withdrawal: {
            id: withdrawalId,
            farmerId: uid,
            amount,
            minimumReserve: 0,
            commissionReserveBalance: wallet.commissionReserveBalance,
            commissionReserveHeld: wallet.commissionReserveHeld,
            payoutFee: 0,
            netAmount: amount,
            payoutMethod: "gcash",
            accountName: payoutAccount.accountName,
            postalCode: payoutAccount.postalCode || "",
            accountNumberMasked: payoutAccount.accountNumberMasked,
            status: "processing",
            idempotencyKey,
            xenditPayoutId: payout?.payout_id || payout?.id || null,
            xenditReferenceId: payout?.reference_id || referenceId,
            requestedAt: now,
            processingAt: new Date(),
          },
          withdrawableAmount: getWithdrawableAmount({
            ...wallet,
            availableBalance: availableAfterReserve,
          }),
        });
      } catch (payoutError) {
        await db.runTransaction(async (transaction) => {
          const freshWalletSnap = await transaction.get(walletRef);
          const freshWallet = sanitizeWallet(uid, freshWalletSnap.exists ? freshWalletSnap.data() : {});

          transaction.set(
            walletRef,
            {
              ...freshWallet,
              reservedBalance: Math.max(
                0,
                roundMoney(freshWallet.reservedBalance - amount)
              ),
              availableBalance: roundMoney(freshWallet.availableBalance + amount),
              updatedAt: new Date(),
            },
            { merge: true }
          );

          transaction.set(
            withdrawalRef,
            {
              status: "failed",
              failureCode: payoutError?.response?.error_code || null,
              failureReason: payoutError?.message || "Xendit payout request failed.",
              failedAt: new Date(),
              updatedAt: new Date(),
            },
            { merge: true }
          );
        });

        throw payoutError;
      }
    } catch (error) {
      console.error("FARMER WITHDRAW ERROR:", error);
      return res.status(error.status || 400).json({
        success: false,
        error: error.message || "Unable to process withdrawal.",
      });
    }
  });

  router.post("/orders/:orderId/deliver", async (req, res) => {
    try {
      const { decoded } = await requireFarmer(req, auth, db);
      const orderId = String(req.params.orderId);
      const orderRef = db.collection("orders").doc(orderId);

      let settlementResult = null;

      await db.runTransaction(async (transaction) => {
        const [orderSnap, walletSnap] = await Promise.all([
          transaction.get(orderRef),
          transaction.get(db.collection("farmerWallets").doc(decoded.uid)),
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

        const walletRef = db.collection("farmerWallets").doc(decoded.uid);
        const wallet = sanitizeWallet(
          decoded.uid,
          walletSnap.exists ? walletSnap.data() : {}
        );
        const commission = getCodCommission(order);
        const commissionAmount = commission.amount;
        const now = new Date();

        let nextAvailable = wallet.availableBalance;
        let nextReserve = wallet.commissionReserveBalance;
        let nextHeld = wallet.commissionReserveHeld;
        let farmerEarning = 0;

        if (order.payment === "gcash") {
          farmerEarning = roundMoney(commission.subtotal - commissionAmount);
          nextAvailable = roundMoney(wallet.availableBalance + farmerEarning);
        } else if (order.payment === "cod") {
          const reservedAmount = roundMoney(order.codCommissionReserved);

          if (
            order.codCommissionReservationStatus !== "reserved" ||
            reservedAmount + 0.001 < commissionAmount ||
            wallet.commissionReserveHeld + 0.001 < commissionAmount
          ) {
            throw new Error(
              `COD commission reserve is not available for this order. Required: ₱${commissionAmount.toFixed(2)}.`
            );
          }

          nextHeld = Math.max(0, roundMoney(wallet.commissionReserveHeld - commissionAmount));
          nextReserve = wallet.commissionReserveBalance;
        }

        transaction.set(
          walletRef,
          {
            ...wallet,
            availableBalance: nextAvailable,
            commissionReserveBalance: nextReserve,
            commissionReserveHeld: nextHeld,
            totalEarned:
              order.payment === "gcash"
                ? roundMoney(wallet.totalEarned + farmerEarning)
                : wallet.totalEarned,
            totalGcashEarnings:
              order.payment === "gcash"
                ? roundMoney(wallet.totalGcashEarnings + farmerEarning)
                : wallet.totalGcashEarnings,
            totalCodCommissionPaid:
              order.payment === "cod"
                ? roundMoney(wallet.totalCodCommissionPaid + commissionAmount)
                : wallet.totalCodCommissionPaid,
            updatedAt: now,
          },
          { merge: true }
        );

        const commissionTxnRef = db.collection("walletTransactions").doc();
        transaction.set(commissionTxnRef, {
          farmerId: decoded.uid,
          type:
            order.payment === "cod"
              ? "cod_commission_debit"
              : "gcash_commission",
          direction:
            order.payment === "cod"
              ? "debit"
              : "memo",
          amount: commissionAmount,
          balanceAfter: nextAvailable,
          commissionReserveAfter: nextReserve,
          commissionReserveHeldAfter: nextHeld,
          orderId,
          orderNumber: order.orderNumber || null,
          status: "completed",
          description:
            order.payment === "cod"
              ? `COD commission collected from the farmer's commission reserve for ${order.orderNumber || orderId}.`
              : `FarmGate commission recorded from GCash order ${order.orderNumber || orderId}.`,
          createdAt: now,
          completedAt: now,
        });

        if (order.payment === "gcash" && farmerEarning > 0) {
          const earningTxnRef = db.collection("walletTransactions").doc();
          transaction.set(earningTxnRef, {
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

        transaction.set(
          db.collection("farmgateTransactions").doc(),
          {
            type: "commission",
            orderId,
            farmerId: decoded.uid,
            amount: commissionAmount,
            direction: "income",
            status: "completed",
            description: `FarmGate commission from order ${order.orderNumber || orderId}.`,
            createdAt: now,
            completedAt: now,
          }
        );

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
          commissionRate: commission.rate,
          commissionAmount,
          commissionStatus: "charged",
          commissionChargedAt: now,
          farmerEarning,
          farmerWalletCredited: order.payment === "gcash",
          farmerWalletCreditedAt: order.payment === "gcash" ? now : null,
          financialStatus: "settled",
          codCommissionReservationStatus:
            order.payment === "cod" ? "consumed" : "not_applicable",
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

      const summaryRef = db
        .collection("farmgateFinancialSummary")
        .doc("summary");
      const summarySnap = await summaryRef.get();

      const summary = summarySnap.exists
        ? summarySnap.data() || {}
        : {};

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

      if (callbackToken !== expectedToken) {
        return res.status(401).json({ success: false, error: "Invalid payout webhook token." });
      }

      const event = String(req.body?.event || "");
      const data = req.body?.data || {};
      const withdrawalDoc = await findWithdrawal({
        db,
        payoutId: data?.payout_id,
        referenceId: data?.reference_id,
      });

      if (!withdrawalDoc) {
        return res.status(200).json({
          success: true,
          message: "Webhook acknowledged. Withdrawal not found.",
        });
      }

      await applyWithdrawalWebhook({ db, withdrawalDoc, data, event });
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
};
