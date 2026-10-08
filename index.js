const express = require("express");
const cors = require("cors");
const cloudinary = require("cloudinary").v2;
const crypto = require("crypto");
require("dotenv").config();

const {
  createWalletRouter,
  handleCommissionDepositWebhook,
} = require("./walletRoutes");

const {
  initializeApp,
  getApps,
  getApp,
  cert,
} = require("firebase-admin/app");

const { getAuth } = require("firebase-admin/auth");

const { getFirestore, FieldValue } = require("firebase-admin/firestore");

const app = express();

app.use(cors());

app.use(
  express.json({
    limit: "2mb",
  })
);

/* =========================================================
   ENVIRONMENT HELPERS
========================================================= */

const getEnv = (name) => {
  const value = process.env[name];

  if (typeof value !== "string" || value.trim() === "") {
    return undefined;
  }

  return value.trim();
};

// Safe: invalid values become 0.
const roundMoney = (value) => {
  const number = Number(value);
  if (!Number.isFinite(number)) return 0;
  return Math.round((number + Number.EPSILON) * 100) / 100;
};

const getCommissionRate = () => {
  const configured = Number(getEnv("FARMGATE_COMMISSION_RATE") || 0.03);

  return Number.isFinite(configured) && configured >= 0 ? configured : 0.03;
};

// Must match walletRoutes.js
const getDeliveryFee = () => {
  const configured = Number(getEnv("FARMGATE_DELIVERY_FEE") || 35);

  return Number.isFinite(configured) && configured >= 0 ? configured : 35;
};

const escapeHtml = (value) =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const httpError = (status, message) =>
  Object.assign(new Error(message), { status });

/* =========================================================
   FIREBASE ADMIN
========================================================= */

const firebaseProjectId = getEnv("FIREBASE_PROJECT_ID");
const firebaseClientEmail = getEnv("FIREBASE_CLIENT_EMAIL");

const firebasePrivateKey = process.env.FIREBASE_PRIVATE_KEY
  ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n").trim()
  : undefined;

if (!firebaseProjectId || !firebaseClientEmail || !firebasePrivateKey) {
  throw new Error(
    "Firebase Admin credentials are incomplete. Check FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, and FIREBASE_PRIVATE_KEY."
  );
}

const firebaseApp =
  getApps().length > 0
    ? getApp()
    : initializeApp({
        credential: cert({
          projectId: firebaseProjectId,
          clientEmail: firebaseClientEmail,
          privateKey: firebasePrivateKey,
        }),
      });

const db = getFirestore(firebaseApp);
const auth = getAuth(firebaseApp);

/* =========================================================
   FARMER WALLET / PAYOUT ROUTES
========================================================= */

app.use(
  "/wallet",
  createWalletRouter({
    db,
    auth,
    getEnv,
  })
);

/* =========================================================
   CLOUDINARY
========================================================= */

const cloudinaryCloudName = getEnv("CLOUD_NAME");
const cloudinaryApiKey = getEnv("CLOUD_API_KEY");
const cloudinaryApiSecret = getEnv("CLOUD_API_SECRET");

if (!cloudinaryCloudName || !cloudinaryApiKey || !cloudinaryApiSecret) {
  console.warn("WARNING: Cloudinary environment variables are incomplete.");
}

cloudinary.config({
  cloud_name: cloudinaryCloudName,
  api_key: cloudinaryApiKey,
  api_secret: cloudinaryApiSecret,
});

/* =========================================================
   XENDIT
========================================================= */

const XENDIT_BASE_URL = "https://api.xendit.co";
const XENDIT_API_VERSION = "2024-11-11";
const XENDIT_TIMEOUT_MS = 20000;

/* =========================================================
   CUSTOM ERRORS
========================================================= */

class StockFulfillmentError extends Error {
  constructor(message) {
    super(message);
    this.name = "StockFulfillmentError";
    this.code = "STOCK_UNAVAILABLE";
  }
}

// Payment is valid but the order can no longer be fulfilled automatically.
class FulfillmentBlockedError extends Error {
  constructor(message) {
    super(message);
    this.name = "FulfillmentBlockedError";
    this.code = "FULFILLMENT_BLOCKED";
  }
}

/* =========================================================
   XENDIT AUTH + REQUEST
========================================================= */

const getXenditAuthHeader = () => {
  const secretKey = getEnv("XENDIT_SECRET_KEY");

  if (!secretKey) {
    throw new Error("XENDIT_SECRET_KEY is not configured.");
  }

  return `Basic ${Buffer.from(`${secretKey}:`).toString("base64")}`;
};

const xenditRequest = async (path, options = {}) => {
  const response = await fetch(`${XENDIT_BASE_URL}${path}`, {
    ...options,
    signal: AbortSignal.timeout(XENDIT_TIMEOUT_MS),
    headers: {
      Authorization: getXenditAuthHeader(),
      "Content-Type": "application/json",
      "api-version": XENDIT_API_VERSION,
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
        `Xendit request failed with status ${response.status}`
    );

    error.status = response.status;
    error.response = data;

    throw error;
  }

  return data;
};

/* =========================================================
   FIREBASE AUTH VERIFICATION
========================================================= */

const verifyFirebaseUser = async (req) => {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith("Bearer ")) {
    throw httpError(401, "Missing Firebase authentication token.");
  }

  try {
    return await auth.verifyIdToken(authorization.substring("Bearer ".length));
  } catch {
    throw httpError(401, "Invalid or expired login session.");
  }
};

/* =========================================================
   SAFE STRING COMPARISON
========================================================= */

const safeCompare = (first, second) => {
  if (typeof first !== "string" || typeof second !== "string") {
    return false;
  }

  const firstBuffer = Buffer.from(first, "utf8");
  const secondBuffer = Buffer.from(second, "utf8");

  if (firstBuffer.length !== secondBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(firstBuffer, secondBuffer);
};

/* =========================================================
   MISC HELPERS
========================================================= */

const getRedirectUrl = (actions) => {
  if (!Array.isArray(actions)) return null;

  const redirectAction = actions.find(
    (action) => action?.type === "REDIRECT_CUSTOMER"
  );

  return redirectAction?.value || redirectAction?.url || null;
};

const toMillis = (value) => {
  if (!value) return 0;
  if (typeof value.toMillis === "function") return value.toMillis();
  if (typeof value.seconds === "number") return value.seconds * 1000;
  if (typeof value === "number") return value;

  if (typeof value === "string") {
    const parsed = new Date(value).getTime();
    return Number.isFinite(parsed) ? parsed : 0;
  }

  return 0;
};

const getFreshnessLabel = (batch) => {
  if (!batch?.weekEnd) {
    return batch?.freshness || "";
  }

  const MS_PER_DAY = 24 * 60 * 60 * 1000;

  const daysAgo = Math.floor((Date.now() - toMillis(batch.weekEnd)) / MS_PER_DAY);

  return daysAgo <= 0 ? "Harvested this week" : `Harvested ${daysAgo}d ago`;
};

const getCurrentBatch = (snapshot) => {
  const batches = snapshot.docs
    .map((docSnap) => ({ id: docSnap.id, ...docSnap.data() }))
    .filter((batch) => batch.archived !== true)
    .sort(
      (first, second) =>
        Number(second.batchNumber || 0) - Number(first.batchNumber || 0)
    );

  return batches[0] || null;
};

const getCapturedAmount = (data) =>
  Number(
    data?.captures?.find((capture) => capture?.status === "SUCCEEDED")
      ?.capture_amount ??
      data?.captures?.[0]?.capture_amount ??
      data?.request_amount
  );

/* =========================================================
   FIND ORDER FROM XENDIT WEBHOOK
========================================================= */

const findOrderFromWebhook = async (data) => {
  const metadataOrderId =
    data?.metadata?.orderId || data?.metadata?.order_id || null;

  if (metadataOrderId) {
    const orderSnap = await db
      .collection("orders")
      .doc(String(metadataOrderId))
      .get();

    if (orderSnap.exists) return orderSnap;
  }

  if (data?.payment_request_id) {
    const querySnapshot = await db
      .collection("orders")
      .where("xenditPaymentRequestId", "==", data.payment_request_id)
      .limit(1)
      .get();

    if (!querySnapshot.empty) return querySnapshot.docs[0];
  }

  if (data?.reference_id) {
    const referenceSnapshot = await db
      .collection("orders")
      .where("xenditReferenceId", "==", data.reference_id)
      .limit(1)
      .get();

    if (!referenceSnapshot.empty) return referenceSnapshot.docs[0];

    const orderNumberSnapshot = await db
      .collection("orders")
      .where("orderNumber", "==", data.reference_id)
      .limit(1)
      .get();

    if (!orderNumberSnapshot.empty) return orderNumberSnapshot.docs[0];
  }

  return null;
};

/* =========================================================
   VALIDATE ORDER BEFORE PAYMENT
   - Re-prices everything from the products collection.
   - Locks subtotal / fee / total / commission on the server.
========================================================= */

const validateOrderForPayment = async (orderRef) => {
  return await db.runTransaction(async (transaction) => {
    const orderSnap = await transaction.get(orderRef);

    if (!orderSnap.exists) {
      throw httpError(400, "Order not found.");
    }

    const order = orderSnap.data();

    if (order.payment !== "gcash") {
      throw httpError(400, "Only GCash orders can use Xendit.");
    }

    if (order.status === "cancelled") {
      throw httpError(400, "This order has already been cancelled.");
    }

    // The farmer must accept before the buyer can pay.
    if (order.status !== "accepted") {
      throw httpError(400, "The farmer must accept the order before GCash payment.");
    }

    if (order.paymentStatus === "paid") {
      throw httpError(400, "This order has already been paid.");
    }

    const orderProducts = Array.isArray(order.products) ? order.products : [];

    if (orderProducts.length === 0) {
      throw httpError(400, "Order contains no products.");
    }

    const validatedProducts = [];
    const seenProductIds = new Set();

    let computedSubtotal = 0;

    for (const orderProduct of orderProducts) {
      const productId = String(orderProduct.productId || "");

      if (!productId) {
        throw httpError(400, "Order contains an invalid productId.");
      }

      if (seenProductIds.has(productId)) {
        throw httpError(400, `Duplicate product in order: ${productId}`);
      }

      seenProductIds.add(productId);

      const quantity = Number(orderProduct.quantity);

      if (!Number.isFinite(quantity) || quantity <= 0) {
        throw httpError(400, `Invalid quantity for ${productId}.`);
      }

      const productRef = db.collection("products").doc(productId);
      const productSnap = await transaction.get(productRef);

      if (!productSnap.exists) {
        throw httpError(400, `Product ${productId} not found.`);
      }

      const product = productSnap.data();

      if (product.farmerId !== order.farmerId) {
        throw httpError(400, `Product ${productId} does not belong to this farmer.`);
      }

      if (product.archived === true) {
        throw httpError(400, `Product ${product.name || productId} is archived.`);
      }

      const price = Number(product.price);

      if (!Number.isFinite(price) || price < 0) {
        throw httpError(400, `Invalid price for ${product.name || productId}.`);
      }

      const batchSnapshot = await transaction.get(
        db.collection("productBatches").where("productId", "==", productId)
      );

      const currentBatch = getCurrentBatch(batchSnapshot);

      if (!currentBatch) {
        throw new StockFulfillmentError(
          `No current batch found for ${product.name || productId}.`
        );
      }

      const currentStock = Number(currentBatch.stock);

      if (
        currentBatch.status !== "Available" ||
        !Number.isFinite(currentStock) ||
        currentStock <= 0
      ) {
        throw new StockFulfillmentError(
          `${product.name || productId} is out of stock.`
        );
      }

      if (currentStock < quantity) {
        throw new StockFulfillmentError(
          `Insufficient stock for ${product.name || productId}. Available: ${currentStock}, Requested: ${quantity}.`
        );
      }

      computedSubtotal += roundMoney(price * quantity);

      validatedProducts.push({
        productId,
        batchId: null,
        batchNumber: null,
        harvestRecordId: null,
        contributions: [],
        name: product.name || orderProduct.name || "",
        image: product.image || orderProduct.image || "",
        price,
        quantity,
        unit: product.unit || orderProduct.unit || "",
        reviewed: orderProduct.reviewed || false,
      });
    }

    const deliveryFee = order.delivery === "delivery" ? getDeliveryFee() : 0;

    const finalSubtotal = roundMoney(computedSubtotal);
    const finalTotal = roundMoney(finalSubtotal + deliveryFee);

    if (finalTotal < 1) {
      throw httpError(400, "GCash payment must be at least ₱1.00.");
    }

    if (finalTotal > 100000) {
      throw httpError(400, "GCash payment cannot exceed ₱100,000.00.");
    }

    const commissionRate = getCommissionRate();
    const commissionAmount = roundMoney(finalSubtotal * commissionRate);
    const farmerEarning = roundMoney(
      Math.max(0, finalSubtotal - commissionAmount)
    );

    transaction.update(orderRef, {
      products: validatedProducts,
      subTotal: finalSubtotal,
      deliveryFee,
      total: finalTotal,

      commissionRate,
      commissionAmount,
      farmerEarning,

      payment: "gcash",
      paymentStatus: "pending",
      inventoryFulfilled: false,
      fulfillmentStatus: "pending",
      serverValidated: true,
      serverValidatedAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    });

    return {
      orderId: orderSnap.id,
      orderNumber: order.orderNumber || null,
      buyerId: order.buyerId,
      farmerId: order.farmerId,
      farmName: order.farmName || null,
      total: finalTotal,
      subtotal: finalSubtotal,
      deliveryFee,
      products: validatedProducts,
    };
  });
};

/* =========================================================
   INVENTORY FULFILLMENT (shared by GCash payment and COD processing)

   planInventory       -> READS ONLY  (must run before any write)
   applyInventoryPlans -> WRITES ONLY
========================================================= */

const planInventory = async (transaction, order) => {
  const orderProducts = Array.isArray(order.products) ? order.products : [];

  if (orderProducts.length === 0) {
    throw new Error("Order contains no products.");
  }

  const plans = [];
  const updatedProducts = [];
  const seenProductIds = new Set();

  for (const orderProduct of orderProducts) {
    const productId = String(orderProduct.productId || "");
    const quantity = Number(orderProduct.quantity);

    if (!productId) {
      throw new Error("Invalid product ID in order.");
    }

    if (seenProductIds.has(productId)) {
      throw new Error(`Duplicate product in order: ${productId}`);
    }

    seenProductIds.add(productId);

    if (!Number.isFinite(quantity) || quantity <= 0) {
      throw new Error(`Invalid quantity for ${productId}.`);
    }

    const productRef = db.collection("products").doc(productId);
    const productSnap = await transaction.get(productRef);

    if (!productSnap.exists) {
      throw new Error(`Product ${productId} not found.`);
    }

    const product = productSnap.data();

    if (product.farmerId !== order.farmerId) {
      throw new Error(`Product ${productId} does not belong to the order farmer.`);
    }

    const batchSnapshot = await transaction.get(
      db.collection("productBatches").where("productId", "==", productId)
    );

    const currentBatch = getCurrentBatch(batchSnapshot);

    if (!currentBatch) {
      throw new StockFulfillmentError(
        `No current batch found for ${product.name || productId}.`
      );
    }

    const currentStock = Number(currentBatch.stock);

    if (
      currentBatch.status !== "Available" ||
      !Number.isFinite(currentStock) ||
      currentStock <= 0
    ) {
      throw new StockFulfillmentError(
        `${product.name || productId} is out of stock.`
      );
    }

    if (currentStock < quantity) {
      throw new StockFulfillmentError(
        `Insufficient stock for ${product.name || productId}. Available: ${currentStock}, Requested: ${quantity}.`
      );
    }

    const harvestSnapshot = await transaction.get(
      db.collection("harvestRecords").where("batchId", "==", currentBatch.id)
    );

    // FIFO: oldest harvest first
    const harvestRecords = harvestSnapshot.docs
      .map((harvestDoc) => ({ id: harvestDoc.id, ...harvestDoc.data() }))
      .sort((first, second) => toMillis(first.harvestDate) - toMillis(second.harvestDate))
      .filter((record) => Number(record.remainingQuantity || 0) > 0);

    const contributions = [];
    const harvestUpdates = [];

    let remaining = quantity;

    for (const record of harvestRecords) {
      if (remaining <= 0) break;

      const available = Number(record.remainingQuantity || 0);
      const take = Math.min(available, remaining);

      harvestUpdates.push({
        ref: db.collection("harvestRecords").doc(record.id),
        remainingQuantity: Number((available - take).toFixed(6)),
      });

      contributions.push({
        batchId: currentBatch.id,
        batchNumber: currentBatch.batchNumber,
        harvestRecordId: record.id,
        quantity: take,
      });

      remaining -= take;
    }

    // Legacy fallback: batch stock without harvest records
    if (remaining > 0) {
      contributions.push({
        batchId: currentBatch.id,
        batchNumber: currentBatch.batchNumber,
        harvestRecordId: null,
        quantity: remaining,
      });

      remaining = 0;
    }

    const newStock = Number((currentStock - quantity).toFixed(6));
    const newStatus = newStock <= 0 ? "Out of Stock" : "Available";

    plans.push({
      productId,
      quantity,
      batchRef: db.collection("productBatches").doc(currentBatch.id),
      newStock,
      newStatus,
      freshness: getFreshnessLabel(currentBatch),
      harvestUpdates,
    });

    const primary = contributions[0] || null;

    updatedProducts.push({
      ...orderProduct,
      batchId: primary?.batchId ?? null,
      batchNumber: primary?.batchNumber ?? null,
      harvestRecordId: primary?.harvestRecordId ?? null,
      contributions,
    });
  }

  return { plans, updatedProducts };
};

const applyInventoryPlans = (transaction, plans) => {
  for (const plan of plans) {
    for (const harvestUpdate of plan.harvestUpdates) {
      transaction.update(harvestUpdate.ref, {
        remainingQuantity: harvestUpdate.remainingQuantity,
        updatedAt: FieldValue.serverTimestamp(),
      });
    }

    transaction.update(plan.batchRef, {
      stock: plan.newStock,
      status: plan.newStatus,
      updatedAt: FieldValue.serverTimestamp(),
    });

    const sellable = plan.newStock > 0 && plan.newStatus === "Available";

    transaction.update(db.collection("products").doc(plan.productId), {
      totalSales: FieldValue.increment(plan.quantity),
      weeklySales: FieldValue.increment(plan.quantity),
      monthlySales: FieldValue.increment(plan.quantity),
      stock: plan.newStock,
      status: sellable ? "Available" : "Out of Stock",
      freshness: plan.freshness,
      updatedAt: FieldValue.serverTimestamp(),
    });
  }
};

/* =========================================================
   FULFILL PAID GCASH ORDER
   Money is NOT touched here. The farmer is credited only when the
   order is delivered (wallet route), and "pending" earnings are
   computed from orders on demand.
========================================================= */

const fulfillPaidOrder = async (orderRef, paymentData) => {
  return await db.runTransaction(async (transaction) => {
    const orderSnap = await transaction.get(orderRef);

    if (!orderSnap.exists) {
      throw new Error("Order not found.");
    }

    const order = orderSnap.data();

    // Idempotency
    if (order.inventoryFulfilled === true) {
      return { alreadyFulfilled: true };
    }

    if (order.payment !== "gcash") {
      throw new Error("Only GCash orders can be fulfilled here.");
    }

    // The order may have been cancelled between the webhook pre-check and now.
    if (order.status === "cancelled") {
      throw new FulfillmentBlockedError(
        "Payment received after the order was cancelled."
      );
    }

    const orderTotal = Number(order.total);
    const capturedAmount = getCapturedAmount(paymentData);

    if (!Number.isFinite(orderTotal) || !Number.isFinite(capturedAmount)) {
      throw new Error("Invalid payment amount.");
    }

    if (Math.abs(orderTotal - capturedAmount) > 0.01) {
      throw new Error(
        `Payment amount mismatch. Order: ₱${orderTotal}, Xendit: ₱${capturedAmount}.`
      );
    }

    if (
      order.xenditPaymentRequestId &&
      paymentData?.payment_request_id &&
      order.xenditPaymentRequestId !== paymentData.payment_request_id
    ) {
      throw new Error("Xendit payment request ID does not match the order.");
    }

    if (
      order.xenditReferenceId &&
      paymentData?.reference_id &&
      order.xenditReferenceId !== paymentData.reference_id
    ) {
      throw new Error("Xendit reference ID does not match the order.");
    }

    if (paymentData?.status !== "SUCCEEDED") {
      throw new Error("Payment was not successfully captured.");
    }

    // ---------- READS ----------
    const { plans, updatedProducts } = await planInventory(transaction, order);

    // ---------- WRITES ----------
    applyInventoryPlans(transaction, plans);

    transaction.update(orderRef, {
      paymentStatus: "paid",
      xenditPaymentId: paymentData.payment_id || null,
      xenditPaymentRequestId:
        paymentData.payment_request_id || order.xenditPaymentRequestId || null,
      xenditReferenceId:
        paymentData.reference_id ||
        order.xenditReferenceId ||
        order.orderNumber ||
        null,
      xenditPaymentChannel: paymentData.channel_code || "GCASH",
      xenditPaymentStatus: paymentData.status || "SUCCEEDED",
      paidAt: FieldValue.serverTimestamp(),

      inventoryFulfilled: true,
      fulfillmentStatus: "fulfilled",
      inventoryFulfilledAt: FieldValue.serverTimestamp(),
      fulfillmentError: null,
      products: updatedProducts,

      // Wallet is credited at delivery, not here.
      farmerWalletCredited: false,
      farmerWalletCreditedAt: null,

      xenditWebhookEvent: "payment.capture",
      xenditWebhookReceivedAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    });

    return { alreadyFulfilled: false };
  });
};

/* Records that money arrived but the order needs a human (refund / stock). */
const recordPaidNeedsReview = (orderRef, data, fulfillmentStatus, message) =>
  orderRef.update({
    paymentStatus: "paid",
    xenditPaymentId: data.payment_id || null,
    xenditPaymentRequestId: data.payment_request_id || null,
    xenditReferenceId: data.reference_id || null,
    xenditPaymentChannel: data.channel_code || "GCASH",
    xenditPaymentStatus: data.status || "SUCCEEDED",
    paidAt: FieldValue.serverTimestamp(),

    inventoryFulfilled: false,
    fulfillmentStatus,
    fulfillmentError: message,

    xenditWebhookEvent: "payment.capture",
    xenditWebhookReceivedAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp(),
  });

/* =========================================================
   HOME / HEALTH
========================================================= */

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "FarmGate Backend running...",
  });
});

app.get("/health", (req, res) => {
  res.json({
    success: true,
    backend: "farmgate-backend",
    cloudinary: !!getEnv("CLOUD_NAME"),
    xendit: !!getEnv("XENDIT_SECRET_KEY"),
    xenditWebhook: !!getEnv("XENDIT_WEBHOOK_TOKEN"),
    firebase: !!getEnv("FIREBASE_PROJECT_ID"),
  });
});

/* =========================================================
   DELETE CLOUDINARY IMAGE (authenticated)
========================================================= */

app.post("/delete-image", async (req, res) => {
  try {
    await verifyFirebaseUser(req);

    const { public_id } = req.body || {};

    if (!public_id || typeof public_id !== "string") {
      return res.status(400).json({
        success: false,
        error: "Missing public_id.",
      });
    }

    const result = await cloudinary.uploader.destroy(public_id);

    return res.json({ success: true, result });
  } catch (error) {
    console.error("DELETE IMAGE ERROR:", error);

    return res.status(error.status || 500).json({
      success: false,
      error: error.message,
    });
  }
});

/* =========================================================
   ORDER STATUS: PROCESSING
   - GCash: payment + inventory must already be fulfilled.
   - COD  : stock is deducted HERE, atomically, on the server.
========================================================= */

app.post("/orders/:orderId/process", async (req, res) => {
  try {
    const decoded = await verifyFirebaseUser(req);

    const orderRef = db.collection("orders").doc(String(req.params.orderId));

    await db.runTransaction(async (transaction) => {
      const orderSnap = await transaction.get(orderRef);

      if (!orderSnap.exists) throw httpError(404, "Order not found.");

      const order = orderSnap.data();

      if (order.farmerId !== decoded.uid) {
        throw httpError(403, "You are not authorized to update this order.");
      }

      if (order.status !== "accepted") {
        throw httpError(400, "Only accepted orders can be processed.");
      }

      const processingFields = {
        status: "processing",
        processingAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      };

      if (order.payment === "gcash") {
        if (order.paymentStatus !== "paid") {
          throw httpError(400, "This GCash order has not been paid yet.");
        }

        if (order.inventoryFulfilled !== true) {
          throw httpError(
            400,
            "This GCash order has not been fulfilled from inventory yet."
          );
        }

        transaction.update(orderRef, processingFields);
        return;
      }

      if (order.payment === "cod") {
        if (
          order.codCommissionReservationStatus !== "reserved" ||
          !(Number(order.codCommissionReserved) > 0)
        ) {
          throw httpError(
            400,
            "The COD commission reserve is missing for this order."
          );
        }

        if (order.inventoryFulfilled === true) {
          transaction.update(orderRef, processingFields);
          return;
        }

        // READS first, WRITES after
        const { plans, updatedProducts } = await planInventory(transaction, order);

        applyInventoryPlans(transaction, plans);

        transaction.update(orderRef, {
          ...processingFields,
          products: updatedProducts,
          inventoryFulfilled: true,
          fulfillmentStatus: "fulfilled",
          inventoryFulfilledAt: FieldValue.serverTimestamp(),
        });

        return;
      }

      throw httpError(400, "Order has an invalid payment method.");
    });

    return res.json({ success: true });
  } catch (error) {
    console.error("PROCESS ORDER ERROR:", error);

    const statusCode =
      error.code === "STOCK_UNAVAILABLE" ? 409 : error.status || 400;

    return res.status(statusCode).json({
      success: false,
      error: error.message || "Unable to start processing this order.",
    });
  }
});

/* =========================================================
   ORDER STATUS: TO RECEIVE
========================================================= */

app.post("/orders/:orderId/to-receive", async (req, res) => {
  try {
    const decoded = await verifyFirebaseUser(req);

    const orderRef = db.collection("orders").doc(String(req.params.orderId));

    await db.runTransaction(async (transaction) => {
      const orderSnap = await transaction.get(orderRef);

      if (!orderSnap.exists) throw httpError(404, "Order not found.");

      const order = orderSnap.data();

      if (order.farmerId !== decoded.uid) {
        throw httpError(403, "You are not authorized to update this order.");
      }

      if (order.status !== "processing") {
        throw httpError(
          400,
          "Only processing orders can be marked as To Receive."
        );
      }

      transaction.update(orderRef, {
        status: "to_receive",
        toReceiveAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      });
    });

    return res.json({ success: true });
  } catch (error) {
    console.error("TO RECEIVE ERROR:", error);

    return res.status(error.status || 400).json({
      success: false,
      error: error.message || "Unable to update this order.",
    });
  }
});

/* =========================================================
   CREATE XENDIT PAYMENT
========================================================= */

app.post("/create-payment", async (req, res) => {
  try {
    const { orderId } = req.body || {};

    if (!orderId) {
      return res.status(400).json({
        success: false,
        error: "Missing orderId.",
      });
    }

    const decodedUser = await verifyFirebaseUser(req);

    const orderRef = db.collection("orders").doc(String(orderId));
    const orderSnap = await orderRef.get();

    if (!orderSnap.exists) {
      return res.status(404).json({
        success: false,
        error: "Order not found.",
      });
    }

    const order = orderSnap.data();

    if (order.buyerId !== decodedUser.uid) {
      return res.status(403).json({
        success: false,
        error: "You are not authorized to pay for this order.",
      });
    }

    if (order.payment !== "gcash") {
      return res.status(400).json({
        success: false,
        error: "This order is not a GCash order.",
      });
    }

    if (order.status === "cancelled") {
      return res.status(400).json({
        success: false,
        error: "This order has already been cancelled.",
      });
    }

    if (order.paymentStatus === "paid") {
      return res.json({
        success: true,
        alreadyPaid: true,
        orderId,
        paymentStatus: "paid",
      });
    }

    // Re-prices the order and enforces status === "accepted".
    const validated = await validateOrderForPayment(orderRef);

    const publicBaseUrl = String(process.env.PUBLIC_BASE_URL || "")
      .trim()
      .replace(/\/+$/, "");

    if (!publicBaseUrl) {
      return res.status(500).json({
        success: false,
        error: "PUBLIC_BASE_URL is not configured.",
      });
    }

    // Reuse a still-open payment request (prevents double payments).
    const latestOrderSnap = await orderRef.get();
    const latestOrder = latestOrderSnap.data() || {};

    if (latestOrder.xenditPaymentRequestId) {
      try {
        const existingPayment = await xenditRequest(
          `/v3/payment_requests/${encodeURIComponent(
            latestOrder.xenditPaymentRequestId
          )}`,
          { method: "GET" }
        );

        const redirectUrl = getRedirectUrl(existingPayment.actions);

        const requestedAmount = Number(existingPayment.request_amount);

        const amountStillMatches =
          !Number.isFinite(requestedAmount) ||
          Math.abs(requestedAmount - validated.total) <= 0.01;

        if (
          redirectUrl &&
          amountStillMatches &&
          ["PENDING", "REQUIRES_ACTION"].includes(existingPayment.status)
        ) {
          return res.json({
            success: true,
            existingPayment: true,
            orderId,
            orderNumber: validated.orderNumber || null,
            paymentRequestId:
              existingPayment.payment_request_id || existingPayment.id || null,
            referenceId: existingPayment.reference_id || null,
            paymentStatus: existingPayment.status,
            amount: validated.total,
            redirectUrl,
          });
        }
      } catch (error) {
        console.log("EXISTING PAYMENT LOOKUP ERROR:", error.message);
      }
    }

    const referenceId = `${validated.orderNumber || orderId}-${Date.now()}`;

    const successReturnUrl = `${publicBaseUrl}/payment/success?orderId=${encodeURIComponent(orderId)}`;
    const failureReturnUrl = `${publicBaseUrl}/payment/failure?orderId=${encodeURIComponent(orderId)}`;

    const payload = {
      reference_id: referenceId,
      type: "PAY",
      country: "PH",
      currency: "PHP",
      request_amount: Number(validated.total.toFixed(2)),
      capture_method: "AUTOMATIC",
      channel_code: "GCASH",
      channel_properties: {
        success_return_url: successReturnUrl,
        failure_return_url: failureReturnUrl,
      },
      description: `FarmGate Order ${validated.orderNumber || orderId}`,
      metadata: {
        orderId: String(orderId),
        orderNumber: String(validated.orderNumber || ""),
        buyerId: String(validated.buyerId),
      },
    };

    console.log("CREATING XENDIT PAYMENT:", {
      orderId,
      referenceId,
      amount: validated.total,
    });

    const paymentRequest = await xenditRequest("/v3/payment_requests", {
      method: "POST",
      body: JSON.stringify(payload),
    });

    const redirectUrl = getRedirectUrl(paymentRequest.actions);

    if (!redirectUrl) {
      console.error("XENDIT DID NOT RETURN REDIRECT:", paymentRequest);

      return res.status(502).json({
        success: false,
        error: "Xendit did not return a customer redirect URL.",
      });
    }

    await orderRef.update({
      paymentStatus: "pending",
      xenditPaymentRequestId:
        paymentRequest.payment_request_id || paymentRequest.id || null,
      xenditReferenceId: paymentRequest.reference_id || referenceId,
      xenditPaymentChannel: paymentRequest.channel_code || "GCASH",
      xenditPaymentStatus: paymentRequest.status || "PENDING",
      inventoryFulfilled: false,
      fulfillmentStatus: "pending",
      paymentRequestCreatedAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    });

    return res.json({
      success: true,
      orderId,
      orderNumber: validated.orderNumber || null,
      paymentRequestId:
        paymentRequest.payment_request_id || paymentRequest.id || null,
      referenceId: paymentRequest.reference_id || referenceId,
      paymentStatus: paymentRequest.status || "PENDING",
      paymentChannel: paymentRequest.channel_code || "GCASH",
      amount: validated.total,
      redirectUrl,
    });
  } catch (error) {
    console.error("CREATE PAYMENT ERROR:", error);

    const statusCode =
      error.code === "STOCK_UNAVAILABLE" ? 409 : error.status || 500;

    return res.status(statusCode).json({
      success: false,
      error: error.message || "Unable to create Xendit payment.",
      details: error.response || null,
    });
  }
});

/* =========================================================
   GET PAYMENT STATUS (read-only, never calls Xendit)
========================================================= */

app.get("/payment-status/:orderId", async (req, res) => {
  try {
    const { orderId } = req.params;

    const decodedUser = await verifyFirebaseUser(req);

    const orderSnap = await db.collection("orders").doc(String(orderId)).get();

    if (!orderSnap.exists) {
      return res.status(404).json({
        success: false,
        error: "Order not found.",
      });
    }

    const order = orderSnap.data();

    if (order.buyerId !== decodedUser.uid) {
      return res.status(403).json({
        success: false,
        error: "You are not authorized to view this order.",
      });
    }

    return res.json({
      success: true,
      orderId,
      payment: order.payment || null,
      paymentStatus: order.paymentStatus || "pending",
      inventoryFulfilled: order.inventoryFulfilled === true,
      fulfillmentStatus: order.fulfillmentStatus || "pending",
      xenditPaymentRequestId: order.xenditPaymentRequestId || null,
      xenditPaymentId: order.xenditPaymentId || null,
      xenditReferenceId: order.xenditReferenceId || null,
      xenditPaymentChannel: order.xenditPaymentChannel || null,
      xenditPaymentStatus: order.xenditPaymentStatus || null,
      paymentFailureCode: order.paymentFailureCode || null,
      paymentFailureReason: order.paymentFailureReason || null,
      paymentRequestCreatedAt: order.paymentRequestCreatedAt || null,
      paidAt: order.paidAt || null,
      serverValidated: order.serverValidated === true,
      serverValidatedAt: order.serverValidatedAt || null,
      xenditWebhookEvent: order.xenditWebhookEvent || null,
      xenditWebhookReceivedAt: order.xenditWebhookReceivedAt || null,
      fulfillmentError: order.fulfillmentError || null,
      updatedAt: order.updatedAt || null,
    });
  } catch (error) {
    console.error("PAYMENT STATUS ERROR:", error);

    return res.status(error.status || 500).json({
      success: false,
      error: error.message || "Unable to get payment status.",
    });
  }
});

/* =========================================================
   XENDIT WEBHOOK
========================================================= */

app.post("/webhooks/xendit", async (req, res) => {
  try {
    const callbackToken = req.headers["x-callback-token"];
    const webhookToken = getEnv("XENDIT_WEBHOOK_TOKEN");

    if (!webhookToken) {
      console.error("XENDIT_WEBHOOK_TOKEN is missing.");

      return res.status(500).json({
        success: false,
        error: "Webhook token is not configured.",
      });
    }

    if (!callbackToken || typeof callbackToken !== "string") {
      console.error("Missing Xendit callback token.");

      return res.status(401).json({
        success: false,
        error: "Missing Xendit callback token.",
      });
    }

    if (!safeCompare(callbackToken, webhookToken)) {
      console.error("Invalid Xendit callback token.");

      return res.status(401).json({
        success: false,
        error: "Invalid Xendit callback token.",
      });
    }

    const event = req.body?.event;
    const data = req.body?.data || {};

    console.log("XENDIT WEBHOOK RECEIVED:", {
      event,
      paymentId: data.payment_id,
      paymentRequestId: data.payment_request_id,
      referenceId: data.reference_id,
      channel: data.channel_code,
      status: data.status,
      requestAmount: data.request_amount,
    });

    /* ---------- COMMISSION RESERVE DEPOSIT WEBHOOK ---------- */

    const depositWebhook = await handleCommissionDepositWebhook({
      db,
      event,
      data,
    });

    if (depositWebhook?.handled) {
      return res.status(200).json({
        success: true,
        message: depositWebhook?.failed
          ? "Commission reserve deposit payment failure recorded."
          : depositWebhook?.manualReview
            ? "Commission reserve deposit requires manual review."
            : "Commission reserve deposit webhook handled.",
        deposit: depositWebhook,
      });
    }

    /* ---------- AUTHORIZATION ---------- */

    if (event === "payment.authorization") {
      return res.status(200).json({
        success: true,
        message: "Payment authorization webhook acknowledged.",
      });
    }

    /* ---------- FAILURE ---------- */

    if (event === "payment.failure") {
      const orderSnap = await findOrderFromWebhook(data);

      if (!orderSnap) {
        console.error("ORDER NOT FOUND FOR PAYMENT FAILURE.");

        return res.status(200).json({
          success: true,
          message: "Webhook acknowledged; order not found.",
        });
      }

      const order = orderSnap.data();

      // A failure of an old attempt must never undo a paid order.
      if (order.paymentStatus === "paid") {
        return res.status(200).json({
          success: true,
          message: "Order is already paid.",
        });
      }

      await db.collection("orders").doc(orderSnap.id).update({
        paymentStatus: "failed",
        xenditPaymentId: data.payment_id || null,
        xenditPaymentRequestId: data.payment_request_id || null,
        xenditReferenceId: data.reference_id || null,
        xenditPaymentChannel: data.channel_code || "GCASH",
        xenditPaymentStatus: data.status || "FAILED",
        paymentFailureCode: data.failure_code || data.error_code || null,
        paymentFailureReason:
          data.failure_reason || data.failure_message || data.message || null,
        fulfillmentStatus: "pending",
        inventoryFulfilled: false,
        updatedAt: FieldValue.serverTimestamp(),
        xenditWebhookEvent: "payment.failure",
        xenditWebhookReceivedAt: FieldValue.serverTimestamp(),
      });

      console.log(`Payment failure saved for order ${orderSnap.id}`);

      return res.status(200).json({
        success: true,
        message: "Payment failure recorded.",
      });
    }

    /* ---------- ONLY payment.capture FULFILLS ---------- */

    if (event !== "payment.capture") {
      console.log("Webhook acknowledged; no fulfillment required:", event);

      return res.status(200).json({
        success: true,
        message: "Webhook acknowledged; no fulfillment required.",
      });
    }

    if (data.status !== "SUCCEEDED") {
      console.error("Payment capture is not successful:", data.status);

      return res.status(200).json({
        success: true,
        message: "Payment capture received but payment is not successful.",
      });
    }

    if (data.channel_code && data.channel_code !== "GCASH") {
      console.error("Unexpected payment channel:", data.channel_code);

      return res.status(400).json({
        success: false,
        error: "Unexpected payment channel.",
      });
    }

    const orderSnap = await findOrderFromWebhook(data);

    if (!orderSnap) {
      console.error("ORDER NOT FOUND FOR PAYMENT CAPTURE:", {
        paymentId: data.payment_id,
        paymentRequestId: data.payment_request_id,
        referenceId: data.reference_id,
      });

      return res.status(200).json({
        success: true,
        message: "Webhook acknowledged; order not found.",
      });
    }

    const orderRef = db.collection("orders").doc(orderSnap.id);
    const order = orderSnap.data();

    /* ---------- DUPLICATE PAYMENT FOR AN ALREADY-PAID ORDER ---------- */

    if (
      order.paymentStatus === "paid" &&
      order.xenditPaymentId &&
      data.payment_id &&
      order.xenditPaymentId !== data.payment_id
    ) {
      await orderRef.update({
        duplicatePaymentNeedsRefund: true,
        duplicatePaymentIds: FieldValue.arrayUnion(data.payment_id),
        updatedAt: FieldValue.serverTimestamp(),
      });

      console.warn(
        `Duplicate payment ${data.payment_id} for already-paid order ${orderSnap.id}. Refund required.`
      );

      return res.status(200).json({
        success: true,
        message: "Duplicate payment recorded for manual refund.",
      });
    }

    /* ---------- ALREADY FULFILLED (idempotent retry) ---------- */

    if (order.inventoryFulfilled === true && order.paymentStatus === "paid") {
      console.log(`Order ${orderSnap.id} already fulfilled.`);

      return res.status(200).json({
        success: true,
        message: "Order already fulfilled.",
        orderId: orderSnap.id,
        inventoryFulfilled: true,
        alreadyFulfilled: true,
      });
    }

    /* ---------- REQUEST / REFERENCE MISMATCH -> MANUAL REVIEW ---------- */
    /* Money arrived, so never answer 400 and lose track of it. */

    const requestMismatch =
      order.xenditPaymentRequestId &&
      data.payment_request_id &&
      order.xenditPaymentRequestId !== data.payment_request_id;

    const referenceMismatch =
      order.xenditReferenceId &&
      data.reference_id &&
      order.xenditReferenceId !== data.reference_id;

    if (requestMismatch || referenceMismatch) {
      await recordPaidNeedsReview(
        orderRef,
        data,
        "manual_review",
        "Payment came from a different payment request than the one saved on the order."
      );

      console.error("PAYMENT REQUEST/REFERENCE MISMATCH:", orderSnap.id);

      return res.status(200).json({
        success: true,
        message: "Payment received but request mismatch requires manual review.",
      });
    }

    /* ---------- AMOUNT CHECK ---------- */

    const orderTotal = Number(order.total);
    const capturedAmount = getCapturedAmount(data);

    if (!Number.isFinite(orderTotal) || !Number.isFinite(capturedAmount)) {
      await recordPaidNeedsReview(
        orderRef,
        data,
        "manual_review",
        "Invalid payment amount."
      );

      return res.status(200).json({
        success: true,
        message: "Payment received but amount is invalid; manual review required.",
      });
    }

    if (Math.abs(orderTotal - capturedAmount) > 0.01) {
      console.error("PAYMENT AMOUNT MISMATCH:", { orderTotal, capturedAmount });

      await recordPaidNeedsReview(
        orderRef,
        data,
        "manual_review",
        "Payment amount does not match the order total."
      );

      return res.status(200).json({
        success: true,
        message:
          "Payment received but amount mismatch requires manual review.",
      });
    }

    /* ---------- CANCELLED ORDER ---------- */

    if (order.status === "cancelled") {
      await recordPaidNeedsReview(
        orderRef,
        data,
        "manual_review",
        "Payment received after the order was cancelled."
      );

      console.warn(
        `Cancelled order ${orderSnap.id} received payment. Manual review required.`
      );

      return res.status(200).json({
        success: true,
        message:
          "Payment received for cancelled order; manual review required.",
      });
    }

    /* ---------- SERVER-SIDE FIFO FULFILLMENT ---------- */

    try {
      const result = await fulfillPaidOrder(orderRef, data);

      console.log("PAYMENT + FULFILLMENT COMPLETE:", {
        orderId: orderSnap.id,
        alreadyFulfilled: result.alreadyFulfilled,
      });

      return res.status(200).json({
        success: true,
        message: result.alreadyFulfilled
          ? "Order already fulfilled."
          : "Payment captured and inventory fulfilled.",
        orderId: orderSnap.id,
        inventoryFulfilled: true,
        alreadyFulfilled: result.alreadyFulfilled,
      });
    } catch (fulfillmentError) {
      if (
        fulfillmentError.code === "STOCK_UNAVAILABLE" ||
        fulfillmentError.code === "FULFILLMENT_BLOCKED"
      ) {
        await recordPaidNeedsReview(
          orderRef,
          data,
          fulfillmentError.code === "STOCK_UNAVAILABLE"
            ? "stock_unavailable"
            : "manual_review",
          fulfillmentError.message
        );

        console.error(
          "PAYMENT SUCCESS BUT FULFILLMENT BLOCKED:",
          fulfillmentError.message
        );

        // Payment succeeded, so acknowledge. The order is flagged for a human.
        return res.status(200).json({
          success: true,
          message: "Payment received but order requires manual review.",
          orderId: orderSnap.id,
        });
      }

      throw fulfillmentError;
    }
  } catch (error) {
    console.error("XENDIT WEBHOOK ERROR:", error);

    return res.status(500).json({
      success: false,
      error: error.message || "Webhook processing failed.",
    });
  }
});

/* =========================================================
   PAYMENT RESULT PAGES (all user input is HTML-escaped)
========================================================= */

const renderPaymentPage = ({ title, heading, lines, orderId }) => `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(title)}</title>
</head>
<body style="font-family: Arial, sans-serif; text-align: center; padding: 40px;">
  <h2>${escapeHtml(heading)}</h2>
  ${lines.map((line) => `<p>${escapeHtml(line)}</p>`).join("\n  ")}
  ${orderId ? `<p>Order ID: <strong>${escapeHtml(orderId)}</strong></p>` : ""}
</body>
</html>`;

app.get("/payment/success", (req, res) => {
  const orderId = String(req.query.orderId || "");

  res.status(200).send(
    renderPaymentPage({
      title: "FarmGate Payment",
      heading: "Payment Submitted",
      lines: [
        "Your GCash payment has been submitted.",
        "FarmGate is waiting for the final payment confirmation.",
        "You can return to the FarmGate app.",
      ],
      orderId,
    })
  );
});

app.get("/payment/failure", (req, res) => {
  const orderId = String(req.query.orderId || "");

  res.status(200).send(
    renderPaymentPage({
      title: "FarmGate Payment Failed",
      heading: "Payment Failed",
      lines: [
        "The GCash payment was not completed.",
        "Return to FarmGate and try again.",
      ],
      orderId,
    })
  );
});

/* =========================================================
   404
========================================================= */

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Route not found.",
    path: req.originalUrl,
  });
});

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {
  console.error("GLOBAL ERROR:", error);

  if (res.headersSent) {
    return next(error);
  }

  return res.status(500).json({
    success: false,
    error: error.message || "Internal server error.",
  });
});

/* =========================================================
   START SERVER
========================================================= */

const PORT = process.env.PORT || 5000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("========================================");
  console.log(`FarmGate Backend running on port ${PORT}`);
  console.log(`Cloudinary configured: ${!!getEnv("CLOUD_NAME")}`);
  console.log(`Firebase configured: ${!!getEnv("FIREBASE_PROJECT_ID")}`);
  console.log(`Xendit configured: ${!!getEnv("XENDIT_SECRET_KEY")}`);
  console.log(`Xendit webhook configured: ${!!getEnv("XENDIT_WEBHOOK_TOKEN")}`);
  console.log(`PUBLIC_BASE_URL: ${getEnv("PUBLIC_BASE_URL") || "NOT SET"}`);
  console.log("========================================");
});