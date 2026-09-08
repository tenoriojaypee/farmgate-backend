const express = require("express");
const cors = require("cors");
const cloudinary = require("cloudinary").v2;
const crypto = require("crypto");
require("dotenv").config();

const {
  initializeApp,
  getApps,
  getApp,
  cert,
} = require("firebase-admin/app");

const { getAuth } = require("firebase-admin/auth");

const {
  getFirestore,
  FieldValue,
} = require("firebase-admin/firestore");

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

/* =========================================================
   FIREBASE ADMIN
========================================================= */

const firebaseProjectId = getEnv("FIREBASE_PROJECT_ID");
const firebaseClientEmail = getEnv("FIREBASE_CLIENT_EMAIL");

const firebasePrivateKey = process.env.FIREBASE_PRIVATE_KEY
  ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n").trim()
  : undefined;

if (
  !firebaseProjectId ||
  !firebaseClientEmail ||
  !firebasePrivateKey
) {
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
   CLOUDINARY
========================================================= */

const cloudinaryCloudName = getEnv("CLOUD_NAME");
const cloudinaryApiKey = getEnv("CLOUD_API_KEY");
const cloudinaryApiSecret = getEnv("CLOUD_API_SECRET");

if (
  !cloudinaryCloudName ||
  !cloudinaryApiKey ||
  !cloudinaryApiSecret
) {
  console.warn(
    "WARNING: Cloudinary environment variables are incomplete."
  );
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

/* =========================================================
   CUSTOM STOCK ERROR
========================================================= */

class StockFulfillmentError extends Error {
  constructor(message) {
    super(message);
    this.name = "StockFulfillmentError";
    this.code = "STOCK_UNAVAILABLE";
  }
}

/* =========================================================
   XENDIT AUTH
========================================================= */

const getXenditAuthHeader = () => {
  const secretKey = getEnv("XENDIT_SECRET_KEY");

  if (!secretKey) {
    throw new Error("XENDIT_SECRET_KEY is not configured.");
  }

  const encoded = Buffer.from(`${secretKey}:`).toString("base64");

  return `Basic ${encoded}`;
};

/* =========================================================
   XENDIT REQUEST
========================================================= */

const xenditRequest = async (path, options = {}) => {
  const response = await fetch(`${XENDIT_BASE_URL}${path}`, {
    ...options,
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
    data = {
      raw: text,
    };
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

  if (
    !authorization ||
    !authorization.startsWith("Bearer ")
  ) {
    throw new Error(
      "Missing Firebase authentication token."
    );
  }

  const token = authorization.substring("Bearer ".length);

  return await auth.verifyIdToken(token);
};

/* =========================================================
   SAFE STRING COMPARISON
========================================================= */

const safeCompare = (first, second) => {
  if (
    typeof first !== "string" ||
    typeof second !== "string"
  ) {
    return false;
  }

  const firstBuffer = Buffer.from(first, "utf8");
  const secondBuffer = Buffer.from(second, "utf8");

  if (firstBuffer.length !== secondBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(
    firstBuffer,
    secondBuffer
  );
};

/* =========================================================
   REDIRECT URL
========================================================= */

const getRedirectUrl = (actions) => {
  if (!Array.isArray(actions)) {
    return null;
  }

  const redirectAction = actions.find(
    (action) => action?.type === "REDIRECT_CUSTOMER"
  );

  return redirectAction?.value || null;
};

/* =========================================================
   FIRESTORE TIMESTAMP TO MILLISECONDS
========================================================= */

const toMillis = (value) => {
  if (!value) {
    return 0;
  }

  if (typeof value.toMillis === "function") {
    return value.toMillis();
  }

  if (typeof value.seconds === "number") {
    return value.seconds * 1000;
  }

  if (typeof value === "number") {
    return value;
  }

  if (typeof value === "string") {
    const parsed = new Date(value).getTime();

    return Number.isFinite(parsed) ? parsed : 0;
  }

  return 0;
};

/* =========================================================
   FRESHNESS
========================================================= */

const getFreshnessLabel = (batch) => {
  if (!batch?.weekEnd) {
    return batch?.freshness || "";
  }

  const MS_PER_DAY = 24 * 60 * 60 * 1000;

  const daysAgo = Math.floor(
    (Date.now() - toMillis(batch.weekEnd)) /
      MS_PER_DAY
  );

  return daysAgo <= 0
    ? "Harvested this week"
    : `Harvested ${daysAgo}d ago`;
};

/* =========================================================
   GET CURRENT BATCH
========================================================= */

const getCurrentBatch = (snapshot) => {
  const batches = snapshot.docs
    .map((docSnap) => ({
      id: docSnap.id,
      ...docSnap.data(),
    }))
    .filter((batch) => batch.archived !== true)
    .sort(
      (first, second) =>
        Number(second.batchNumber || 0) -
        Number(first.batchNumber || 0)
    );

  return batches[0] || null;
};

/* =========================================================
   FIND ORDER FROM XENDIT WEBHOOK
========================================================= */

const findOrderFromWebhook = async (data) => {
  /* -------------------------------------------------------
     1. metadata.orderId
  ------------------------------------------------------- */

  const metadataOrderId =
    data?.metadata?.orderId ||
    data?.metadata?.order_id ||
    null;

  if (metadataOrderId) {
    const orderSnap = await db
      .collection("orders")
      .doc(String(metadataOrderId))
      .get();

    if (orderSnap.exists) {
      return orderSnap;
    }
  }

  /* -------------------------------------------------------
     2. payment_request_id
  ------------------------------------------------------- */

  if (data?.payment_request_id) {
    const querySnapshot = await db
      .collection("orders")
      .where(
        "xenditPaymentRequestId",
        "==",
        data.payment_request_id
      )
      .limit(1)
      .get();

    if (!querySnapshot.empty) {
      return querySnapshot.docs[0];
    }
  }

  /* -------------------------------------------------------
     3. xenditReferenceId
  ------------------------------------------------------- */

  if (data?.reference_id) {
    const referenceSnapshot = await db
      .collection("orders")
      .where(
        "xenditReferenceId",
        "==",
        data.reference_id
      )
      .limit(1)
      .get();

    if (!referenceSnapshot.empty) {
      return referenceSnapshot.docs[0];
    }

    /* -----------------------------------------------------
       4. orderNumber fallback
    ----------------------------------------------------- */

    const orderNumberSnapshot = await db
      .collection("orders")
      .where(
        "orderNumber",
        "==",
        data.reference_id
      )
      .limit(1)
      .get();

    if (!orderNumberSnapshot.empty) {
      return orderNumberSnapshot.docs[0];
    }
  }

  return null;
};

/* =========================================================
   VALIDATE ORDER BEFORE PAYMENT
========================================================= */

const validateOrderForPayment = async (orderRef) => {
  return await db.runTransaction(async (transaction) => {
    /* -----------------------------------------------------
       READ ORDER
    ----------------------------------------------------- */

    const orderSnap = await transaction.get(orderRef);

    if (!orderSnap.exists) {
      throw new Error("Order not found.");
    }

    const order = orderSnap.data();

    /* -----------------------------------------------------
       PAYMENT METHOD
    ----------------------------------------------------- */

    if (order.payment !== "gcash") {
      throw new Error(
        "Only GCash orders can use Xendit."
      );
    }

    /* -----------------------------------------------------
       ORDER STATUS
    ----------------------------------------------------- */

    if (order.status === "cancelled") {
      throw new Error(
        "This order has already been cancelled."
      );
    }

    /* -----------------------------------------------------
       ORDER PRODUCTS
    ----------------------------------------------------- */

    const orderProducts = Array.isArray(
      order.products
    )
      ? order.products
      : [];

    if (orderProducts.length === 0) {
      throw new Error(
        "Order contains no products."
      );
    }

    const validatedProducts = [];
    const seenProductIds = new Set();

    let computedSubtotal = 0;

    /* -----------------------------------------------------
       VALIDATE EACH PRODUCT
    ----------------------------------------------------- */

    for (const orderProduct of orderProducts) {
      const productId = String(
        orderProduct.productId || ""
      );

      if (!productId) {
        throw new Error(
          "Order contains an invalid productId."
        );
      }

      if (seenProductIds.has(productId)) {
        throw new Error(
          `Duplicate product in order: ${productId}`
        );
      }

      seenProductIds.add(productId);

      const quantity = Number(
        orderProduct.quantity
      );

      if (
        !Number.isFinite(quantity) ||
        quantity <= 0
      ) {
        throw new Error(
          `Invalid quantity for ${productId}.`
        );
      }

      /* ---------------------------------------------------
         PRODUCT
      --------------------------------------------------- */

      const productRef = db
        .collection("products")
        .doc(productId);

      const productSnap = await transaction.get(
        productRef
      );

      if (!productSnap.exists) {
        throw new Error(
          `Product ${productId} not found.`
        );
      }

      const product = productSnap.data();

      /* ---------------------------------------------------
         FARMER CHECK
      --------------------------------------------------- */

      if (product.farmerId !== order.farmerId) {
        throw new Error(
          `Product ${productId} does not belong to this farmer.`
        );
      }

      /* ---------------------------------------------------
         ARCHIVED CHECK
      --------------------------------------------------- */

      if (product.archived === true) {
        throw new Error(
          `Product ${
            product.name || productId
          } is archived.`
        );
      }

      /* ---------------------------------------------------
         SERVER PRICE
      --------------------------------------------------- */

      const price = Number(product.price);

      if (
        !Number.isFinite(price) ||
        price < 0
      ) {
        throw new Error(
          `Invalid price for ${
            product.name || productId
          }.`
        );
      }

      /* ---------------------------------------------------
         BATCHES
      --------------------------------------------------- */

      const batchQuery = db
        .collection("productBatches")
        .where("productId", "==", productId);

      const batchSnapshot = await transaction.get(
        batchQuery
      );

      const currentBatch =
        getCurrentBatch(batchSnapshot);

      if (!currentBatch) {
        throw new StockFulfillmentError(
          `No current batch found for ${
            product.name || productId
          }.`
        );
      }

      const currentStock = Number(
        currentBatch.stock
      );

      if (
        currentBatch.status !== "Available" ||
        currentStock <= 0
      ) {
        throw new StockFulfillmentError(
          `${
            product.name || productId
          } is out of stock.`
        );
      }

      if (currentStock < quantity) {
        throw new StockFulfillmentError(
          `Insufficient stock for ${
            product.name || productId
          }. Available: ${currentStock}, Requested: ${quantity}.`
        );
      }

      /* ---------------------------------------------------
         SERVER-CALCULATED LINE TOTAL
      --------------------------------------------------- */

      const lineTotal = Number(
        (price * quantity).toFixed(2)
      );

      computedSubtotal += lineTotal;

      validatedProducts.push({
        productId,
        batchId: null,
        batchNumber: null,
        harvestRecordId: null,
        contributions: [],
        name:
          product.name ||
          orderProduct.name ||
          "",
        image:
          product.image ||
          orderProduct.image ||
          "",
        price,
        quantity,
        unit:
          product.unit ||
          orderProduct.unit ||
          "",
        reviewed:
          orderProduct.reviewed || false,
      });
    }

    /* -----------------------------------------------------
       DELIVERY
    ----------------------------------------------------- */

    const delivery =
      order.delivery === "delivery"
        ? "delivery"
        : "pickup";

    const deliveryFee =
      delivery === "delivery" ? 35 : 0;

    const finalSubtotal = Number(
      computedSubtotal.toFixed(2)
    );

    const finalTotal = Number(
      (
        finalSubtotal +
        deliveryFee
      ).toFixed(2)
    );

    /* -----------------------------------------------------
       GCASH PAYMENT LIMITS
    ----------------------------------------------------- */

    if (finalTotal < 1) {
      throw new Error(
        "GCash payment must be at least ₱1.00."
      );
    }

    if (finalTotal > 100000) {
      throw new Error(
        "GCash payment cannot exceed ₱100,000.00."
      );
    }

    /* -----------------------------------------------------
       LOCK SERVER VALUES
    ----------------------------------------------------- */

    transaction.update(orderRef, {
      products: validatedProducts,
      subTotal: finalSubtotal,
      deliveryFee,
      total: finalTotal,
      payment: "gcash",
      paymentStatus: "pending",
      inventoryFulfilled: false,
      fulfillmentStatus: "pending",
      serverValidated: true,
      serverValidatedAt:
        FieldValue.serverTimestamp(),
      updatedAt:
        FieldValue.serverTimestamp(),
    });

    return {
      orderId: orderSnap.id,
      orderNumber:
        order.orderNumber || null,
      buyerId: order.buyerId,
      total: finalTotal,
      subtotal: finalSubtotal,
      deliveryFee,
      products: validatedProducts,
    };
  });
};

/* =========================================================
   FULFILL PAID ORDER
========================================================= */

const fulfillPaidOrder = async (
  orderRef,
  paymentData
) => {
  return await db.runTransaction(async (transaction) => {
    /* -----------------------------------------------------
       READ ORDER
    ----------------------------------------------------- */

    const orderSnap = await transaction.get(orderRef);

    if (!orderSnap.exists) {
      throw new Error("Order not found.");
    }

    const order = orderSnap.data();

    /* -----------------------------------------------------
       IDEMPOTENCY
    ----------------------------------------------------- */

    if (order.inventoryFulfilled === true) {
      return {
        alreadyFulfilled: true,
      };
    }

    /* -----------------------------------------------------
       PAYMENT METHOD
    ----------------------------------------------------- */

    if (order.payment !== "gcash") {
      throw new Error(
        "Only GCash orders can be fulfilled here."
      );
    }

    /* -----------------------------------------------------
       AMOUNT CHECK
    ----------------------------------------------------- */

    const orderTotal = Number(order.total);

    const capturedAmount = Number(
      paymentData?.captures?.[0]
        ?.capture_amount ??
        paymentData?.request_amount
    );

    if (
      !Number.isFinite(orderTotal) ||
      !Number.isFinite(capturedAmount)
    ) {
      throw new Error(
        "Invalid payment amount."
      );
    }

    if (
      Math.abs(
        orderTotal - capturedAmount
      ) > 0.01
    ) {
      throw new Error(
        `Payment amount mismatch. Order: ₱${orderTotal}, Xendit: ₱${capturedAmount}.`
      );
    }

    /* -----------------------------------------------------
       PAYMENT REQUEST ID CHECK
    ----------------------------------------------------- */

    if (
      order.xenditPaymentRequestId &&
      paymentData?.payment_request_id &&
      order.xenditPaymentRequestId !==
        paymentData.payment_request_id
    ) {
      throw new Error(
        "Xendit payment request ID does not match the order."
      );
    }

    /* -----------------------------------------------------
       REFERENCE CHECK
    ----------------------------------------------------- */

    if (
      order.xenditReferenceId &&
      paymentData?.reference_id &&
      order.xenditReferenceId !==
        paymentData.reference_id
    ) {
      throw new Error(
        "Xendit reference ID does not match the order."
      );
    }

    /* -----------------------------------------------------
       PRODUCTS
    ----------------------------------------------------- */

    const orderProducts = Array.isArray(
      order.products
    )
      ? order.products
      : [];

    if (orderProducts.length === 0) {
      throw new Error(
        "Order contains no products."
      );
    }

    const plans = [];
    const updatedProducts = [];

    /* -----------------------------------------------------
       READ + CALCULATE FIFO
    ----------------------------------------------------- */

    for (const orderProduct of orderProducts) {
      const productId = String(
        orderProduct.productId || ""
      );

      const quantity = Number(
        orderProduct.quantity
      );

      if (!productId) {
        throw new Error(
          "Invalid product ID in order."
        );
      }

      if (
        !Number.isFinite(quantity) ||
        quantity <= 0
      ) {
        throw new Error(
          `Invalid quantity for ${productId}.`
        );
      }

      /* ---------------------------------------------------
         PRODUCT
      --------------------------------------------------- */

      const productRef = db
        .collection("products")
        .doc(productId);

      const productSnap = await transaction.get(
        productRef
      );

      if (!productSnap.exists) {
        throw new Error(
          `Product ${productId} not found.`
        );
      }

      const product = productSnap.data();

      /* ---------------------------------------------------
         BATCHES
      --------------------------------------------------- */

      const batchQuery = db
        .collection("productBatches")
        .where("productId", "==", productId);

      const batchSnapshot = await transaction.get(
        batchQuery
      );

      const currentBatch =
        getCurrentBatch(batchSnapshot);

      if (!currentBatch) {
        throw new StockFulfillmentError(
          `No current batch found for ${
            product.name ||
            orderProduct.name ||
            productId
          }.`
        );
      }

      const currentStock = Number(
        currentBatch.stock
      );

      if (
        currentBatch.status !== "Available" ||
        currentStock <= 0
      ) {
        throw new StockFulfillmentError(
          `${
            product.name ||
            orderProduct.name ||
            productId
          } is out of stock.`
        );
      }

      if (currentStock < quantity) {
        throw new StockFulfillmentError(
          `Insufficient stock for ${
            product.name ||
            orderProduct.name ||
            productId
          }. Available: ${currentStock}, Requested: ${quantity}.`
        );
      }

      /* ---------------------------------------------------
         HARVEST RECORDS
      --------------------------------------------------- */

      const harvestQuery = db
        .collection("harvestRecords")
        .where(
          "batchId",
          "==",
          currentBatch.id
        );

      const harvestSnapshot =
        await transaction.get(
          harvestQuery
        );

      /* ---------------------------------------------------
         OLDEST HARVEST FIRST = FIFO
      --------------------------------------------------- */

      const harvestRecords =
        harvestSnapshot.docs
          .map((harvestDoc) => ({
            id: harvestDoc.id,
            ...harvestDoc.data(),
          }))
          .sort(
            (first, second) =>
              toMillis(first.harvestDate) -
              toMillis(second.harvestDate)
          )
          .filter(
            (record) =>
              Number(
                record.remainingQuantity || 0
              ) > 0
          );

      const contributions = [];
      const harvestUpdates = [];

      let remaining = quantity;

      /* ---------------------------------------------------
         FIFO LOOP
      --------------------------------------------------- */

      for (const record of harvestRecords) {
        if (remaining <= 0) {
          break;
        }

        const available = Number(
          record.remainingQuantity || 0
        );

        const take = Math.min(
          available,
          remaining
        );

        const newRemaining = Number(
          (
            available - take
          ).toFixed(6)
        );

        harvestUpdates.push({
          ref: db
            .collection("harvestRecords")
            .doc(record.id),
          remainingQuantity:
            newRemaining,
        });

        contributions.push({
          batchId: currentBatch.id,
          batchNumber:
            currentBatch.batchNumber,
          harvestRecordId: record.id,
          quantity: take,
        });

        remaining -= take;
      }

      /* ---------------------------------------------------
         LEGACY FALLBACK
      --------------------------------------------------- */

      if (remaining > 0) {
        contributions.push({
          batchId: currentBatch.id,
          batchNumber:
            currentBatch.batchNumber,
          harvestRecordId: null,
          quantity: remaining,
        });

        remaining = 0;
      }

      /* ---------------------------------------------------
         NEW BATCH STOCK
      --------------------------------------------------- */

      const newStock = Number(
        (
          currentStock - quantity
        ).toFixed(6)
      );

      const newStatus =
        newStock <= 0
          ? "Out of Stock"
          : "Available";

      plans.push({
        productId,
        quantity,
        batchRef: db
          .collection("productBatches")
          .doc(currentBatch.id),
        newStock,
        newStatus,
        freshness:
          getFreshnessLabel(currentBatch),
        harvestUpdates,
        contributions,
      });

      const primary =
        contributions[0] || null;

      updatedProducts.push({
        ...orderProduct,
        batchId:
          primary?.batchId ?? null,
        batchNumber:
          primary?.batchNumber ?? null,
        harvestRecordId:
          primary?.harvestRecordId ?? null,
        contributions,
      });
    }

    /* -----------------------------------------------------
       WRITES START
    ----------------------------------------------------- */

    /* -----------------------------------------------------
       1. HARVEST RECORDS
    ----------------------------------------------------- */

    for (const plan of plans) {
      for (const harvestUpdate of
        plan.harvestUpdates) {
        transaction.update(
          harvestUpdate.ref,
          {
            remainingQuantity:
              harvestUpdate.remainingQuantity,
            updatedAt:
              FieldValue.serverTimestamp(),
          }
        );
      }
    }

    /* -----------------------------------------------------
       2. BATCH STOCK
    ----------------------------------------------------- */

    for (const plan of plans) {
      transaction.update(
        plan.batchRef,
        {
          stock: plan.newStock,
          status: plan.newStatus,
          updatedAt:
            FieldValue.serverTimestamp(),
        }
      );
    }

    /* -----------------------------------------------------
       3. PRODUCT SALES
    ----------------------------------------------------- */

    for (const plan of plans) {
      const productRef = db
        .collection("products")
        .doc(plan.productId);

      const sellable =
        plan.newStock > 0 &&
        plan.newStatus === "Available";

      transaction.update(
        productRef,
        {
          totalSales:
            FieldValue.increment(
              plan.quantity
            ),
          weeklySales:
            FieldValue.increment(
              plan.quantity
            ),
          monthlySales:
            FieldValue.increment(
              plan.quantity
            ),
          stock: plan.newStock,
          status: sellable
            ? "Available"
            : "Out of Stock",
          freshness: plan.freshness,
          updatedAt:
            FieldValue.serverTimestamp(),
        }
      );
    }

    /* -----------------------------------------------------
       4. ORDER
    ----------------------------------------------------- */

    transaction.update(
      orderRef,
      {
        paymentStatus: "paid",

        xenditPaymentId:
          paymentData.payment_id ||
          null,

        xenditPaymentRequestId:
          paymentData.payment_request_id ||
          order.xenditPaymentRequestId ||
          null,

        xenditReferenceId:
          paymentData.reference_id ||
          order.xenditReferenceId ||
          order.orderNumber ||
          null,

        xenditPaymentChannel:
          paymentData.channel_code ||
          "GCASH",

        xenditPaymentStatus:
          paymentData.status ||
          "SUCCEEDED",

        paidAt:
          FieldValue.serverTimestamp(),

        inventoryFulfilled: true,

        fulfillmentStatus:
          "fulfilled",

        inventoryFulfilledAt:
          FieldValue.serverTimestamp(),

        products: updatedProducts,

        xenditWebhookEvent:
          "payment.capture",

        xenditWebhookReceivedAt:
          FieldValue.serverTimestamp(),

        updatedAt:
          FieldValue.serverTimestamp(),
      }
    );

    return {
      alreadyFulfilled: false,
    };
  });
};

/* =========================================================
   HOME
========================================================= */

app.get("/", (req, res) => {
  res.json({
    success: true,
    message:
      "FarmGate Backend running...",
  });
});

/* =========================================================
   HEALTH CHECK
========================================================= */

app.get("/health", (req, res) => {
  res.json({
    success: true,
    backend: "farmgate-backend",
    cloudinary: !!getEnv("CLOUD_NAME"),
    xendit: !!getEnv("XENDIT_SECRET_KEY"),
    firebase: !!getEnv(
      "FIREBASE_PROJECT_ID"
    ),
  });
});

/* =========================================================
   DELETE CLOUDINARY IMAGE
========================================================= */

app.post(
  "/delete-image",
  async (req, res) => {
    try {
      const { public_id } = req.body;

      if (!public_id) {
        return res.status(400).json({
          success: false,
          error: "Missing public_id.",
        });
      }

      const result =
        await cloudinary.uploader.destroy(
          public_id
        );

      return res.json({
        success: true,
        result,
      });
    } catch (error) {
      console.error(
        "DELETE IMAGE ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }
);

/* =========================================================
   CREATE XENDIT PAYMENT
========================================================= */

app.post(
  "/create-payment",
  async (req, res) => {
    try {
      const { orderId } = req.body;

      if (!orderId) {
        return res.status(400).json({
          success: false,
          error: "Missing orderId.",
        });
      }

      /* ---------------------------------------------------
         VERIFY FIREBASE USER
      --------------------------------------------------- */

      const decodedUser =
        await verifyFirebaseUser(req);

      /* ---------------------------------------------------
         ORDER REFERENCE
      --------------------------------------------------- */

      const orderRef = db
        .collection("orders")
        .doc(String(orderId));

      const orderSnap =
        await orderRef.get();

      if (!orderSnap.exists) {
        return res.status(404).json({
          success: false,
          error: "Order not found.",
        });
      }

      const order = orderSnap.data();

      /* ---------------------------------------------------
         BUYER OWNERSHIP
      --------------------------------------------------- */

      if (
        order.buyerId !==
        decodedUser.uid
      ) {
        return res.status(403).json({
          success: false,
          error:
            "You are not authorized to pay for this order.",
        });
      }

      /* ---------------------------------------------------
         PAYMENT METHOD
      --------------------------------------------------- */

      if (order.payment !== "gcash") {
        return res.status(400).json({
          success: false,
          error:
            "This order is not a GCash order.",
        });
      }

      /* ---------------------------------------------------
         CANCELLED
      --------------------------------------------------- */

      if (order.status === "cancelled") {
        return res.status(400).json({
          success: false,
          error:
            "This order has already been cancelled.",
        });
      }

      /* ---------------------------------------------------
         ALREADY PAID
      --------------------------------------------------- */

      if (order.paymentStatus === "paid") {
        return res.json({
          success: true,
          alreadyPaid: true,
          orderId,
          paymentStatus: "paid",
        });
      }

      /* ---------------------------------------------------
         SERVER VALIDATION FIRST
      --------------------------------------------------- */

      const validated =
        await validateOrderForPayment(
          orderRef
        );

      /* ---------------------------------------------------
         PUBLIC BASE URL
      --------------------------------------------------- */

      const publicBaseUrl = String(
        process.env.PUBLIC_BASE_URL || ""
      )
        .trim()
        .replace(/\/+$/, "");

      if (!publicBaseUrl) {
        return res.status(500).json({
          success: false,
          error:
            "PUBLIC_BASE_URL is not configured.",
        });
      }

      /* ---------------------------------------------------
         TRY REUSE EXISTING PAYMENT
      --------------------------------------------------- */

      const latestOrderSnap =
        await orderRef.get();

      const latestOrder =
        latestOrderSnap.data() || {};

      if (
        latestOrder.xenditPaymentRequestId
      ) {
        try {
          const existingPayment =
            await xenditRequest(
              `/v3/payment_requests/${encodeURIComponent(
                latestOrder.xenditPaymentRequestId
              )}`,
              {
                method: "GET",
              }
            );

          const redirectUrl =
            getRedirectUrl(
              existingPayment.actions
            );

          const reusableStatuses = [
            "PENDING",
            "REQUIRES_ACTION",
          ];

          if (
            redirectUrl &&
            reusableStatuses.includes(
              existingPayment.status
            )
          ) {
            return res.json({
              success: true,
              existingPayment: true,
              orderId,
              orderNumber:
                validated.orderNumber ||
                null,
              paymentRequestId:
                existingPayment.payment_request_id,
              referenceId:
                existingPayment.reference_id,
              paymentStatus:
                existingPayment.status,
              amount: validated.total,
              redirectUrl,
            });
          }
        } catch (error) {
          console.log(
            "EXISTING PAYMENT LOOKUP ERROR:",
            error.message
          );
        }
      }

      /* ---------------------------------------------------
         REFERENCE ID
      --------------------------------------------------- */

      const referenceId =
        `${validated.orderNumber || orderId}-${Date.now()}`;

      /* ---------------------------------------------------
         REDIRECT URLS
      --------------------------------------------------- */

      const successReturnUrl =
        `${publicBaseUrl}/payment/success?orderId=${encodeURIComponent(
          orderId
        )}`;

      const failureReturnUrl =
        `${publicBaseUrl}/payment/failure?orderId=${encodeURIComponent(
          orderId
        )}`;

      /* ---------------------------------------------------
         PAYMENT REQUEST
      --------------------------------------------------- */

      const payload = {
        reference_id: referenceId,
        type: "PAY",
        country: "PH",
        currency: "PHP",
        request_amount: Number(
          validated.total.toFixed(2)
        ),
        capture_method: "AUTOMATIC",
        channel_code: "GCASH",

        channel_properties: {
          success_return_url:
            successReturnUrl,
          failure_return_url:
            failureReturnUrl,
        },

        description:
          `FarmGate Order ${
            validated.orderNumber ||
            orderId
          }`,

        metadata: {
          orderId: String(orderId),
          orderNumber: String(
            validated.orderNumber || ""
          ),
          buyerId: String(
            validated.buyerId
          ),
        },
      };

      console.log(
        "CREATING XENDIT PAYMENT:",
        {
          orderId,
          referenceId,
          amount: validated.total,
        }
      );

      /* ---------------------------------------------------
         SEND TO XENDIT
      --------------------------------------------------- */

      const paymentRequest =
        await xenditRequest(
          "/v3/payment_requests",
          {
            method: "POST",
            body: JSON.stringify(
              payload
            ),
          }
        );

      /* ---------------------------------------------------
         CUSTOMER REDIRECT
      --------------------------------------------------- */

      const redirectUrl =
        getRedirectUrl(
          paymentRequest.actions
        );

      if (!redirectUrl) {
        console.error(
          "XENDIT DID NOT RETURN REDIRECT:",
          paymentRequest
        );

        return res.status(502).json({
          success: false,
          error:
            "Xendit did not return a customer redirect URL.",
        });
      }

      /* ---------------------------------------------------
         SAVE PAYMENT DETAILS
      --------------------------------------------------- */

      await orderRef.update({
        paymentStatus: "pending",

        xenditPaymentRequestId:
          paymentRequest.payment_request_id,

        xenditReferenceId:
          paymentRequest.reference_id,

        xenditPaymentChannel:
          paymentRequest.channel_code ||
          "GCASH",

        xenditPaymentStatus:
          paymentRequest.status,

        inventoryFulfilled: false,

        fulfillmentStatus:
          "pending",

        paymentRequestCreatedAt:
          FieldValue.serverTimestamp(),

        updatedAt:
          FieldValue.serverTimestamp(),
      });

      return res.json({
        success: true,
        orderId,

        orderNumber:
          validated.orderNumber ||
          null,

        paymentRequestId:
          paymentRequest.payment_request_id,

        referenceId:
          paymentRequest.reference_id,

        paymentStatus:
          paymentRequest.status,

        paymentChannel:
          paymentRequest.channel_code ||
          "GCASH",

        amount:
          validated.total,

        redirectUrl,
      });
    } catch (error) {
      console.error(
        "CREATE PAYMENT ERROR:",
        error
      );

      const statusCode =
        error.code === "STOCK_UNAVAILABLE"
          ? 409
          : error.status || 500;

      return res.status(statusCode).json({
        success: false,
        error:
          error.message ||
          "Unable to create Xendit payment.",
        details:
          error.response || null,
      });
    }
  }
);

/* =========================================================
   GET PAYMENT STATUS
========================================================= */

app.get(
  "/payment-status/:orderId",
  async (req, res) => {
    try {
      const { orderId } = req.params;

      /* ---------------------------------------------------
         VERIFY USER
      --------------------------------------------------- */

      const decodedUser =
        await verifyFirebaseUser(req);

      /* ---------------------------------------------------
         ORDER
      --------------------------------------------------- */

      const orderRef = db
        .collection("orders")
        .doc(String(orderId));

      const orderSnap =
        await orderRef.get();

      if (!orderSnap.exists) {
        return res.status(404).json({
          success: false,
          error: "Order not found.",
        });
      }

      const order =
        orderSnap.data();

      /* ---------------------------------------------------
         OWNERSHIP
      --------------------------------------------------- */

      if (
        order.buyerId !==
        decodedUser.uid
      ) {
        return res.status(403).json({
          success: false,
          error:
            "You are not authorized to view this order.",
        });
      }

      return res.json({
        success: true,
        orderId,

        payment:
          order.payment,

        paymentStatus:
          order.paymentStatus ||
          "pending",

        inventoryFulfilled:
          order.inventoryFulfilled ||
          false,

        fulfillmentStatus:
          order.fulfillmentStatus ||
          "pending",

        xenditPaymentRequestId:
          order.xenditPaymentRequestId ||
          null,

        xenditPaymentId:
          order.xenditPaymentId ||
          null,

        xenditReferenceId:
          order.xenditReferenceId ||
          null,
      });
    } catch (error) {
      console.error(
        "PAYMENT STATUS ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          error.message ||
          "Unable to get payment status.",
      });
    }
  }
);

/* =========================================================
   XENDIT WEBHOOK
========================================================= */

app.post(
  "/webhooks/xendit",
  async (req, res) => {
    try {
      /* ---------------------------------------------------
         VERIFY CALLBACK TOKEN
      --------------------------------------------------- */

      const callbackToken =
        req.headers["x-callback-token"];

      const webhookToken =
        getEnv("XENDIT_WEBHOOK_TOKEN");

      if (!webhookToken) {
        console.error(
          "XENDIT_WEBHOOK_TOKEN is missing."
        );

        return res.status(500).json({
          success: false,
          error:
            "Webhook token is not configured.",
        });
      }

      if (
        !callbackToken ||
        typeof callbackToken !== "string"
      ) {
        return res.status(401).json({
          success: false,
          error:
            "Missing Xendit callback token.",
        });
      }

      if (
        !safeCompare(
          callbackToken,
          webhookToken
        )
      ) {
        console.error(
          "Invalid Xendit callback token."
        );

        return res.status(401).json({
          success: false,
          error:
            "Invalid Xendit callback token.",
        });
      }

      /* ---------------------------------------------------
         PAYLOAD
      --------------------------------------------------- */

      const event = req.body?.event;
      const data = req.body?.data || {};

      console.log(
        "XENDIT WEBHOOK RECEIVED:",
        {
          event,
          paymentId:
            data.payment_id,
          paymentRequestId:
            data.payment_request_id,
          referenceId:
            data.reference_id,
          channelCode:
            data.channel_code,
          status:
            data.status,
        }
      );

      /* ---------------------------------------------------
         PAYMENT AUTHORIZATION
      --------------------------------------------------- */

      if (
        event ===
        "payment.authorization"
      ) {
        return res.status(200).json({
          success: true,
          message:
            "Payment authorization webhook acknowledged.",
        });
      }

      /* ---------------------------------------------------
         PAYMENT FAILURE
      --------------------------------------------------- */

      if (
        event ===
        "payment.failure"
      ) {
        const orderSnap =
          await findOrderFromWebhook(
            data
          );

        if (!orderSnap) {
          console.error(
            "ORDER NOT FOUND FOR PAYMENT FAILURE."
          );

          return res.status(200).json({
            success: true,
            message:
              "Webhook acknowledged; order not found.",
          });
        }

        const order =
          orderSnap.data();

        if (
          order.paymentStatus ===
          "paid"
        ) {
          return res.status(200).json({
            success: true,
            message:
              "Order is already paid.",
          });
        }

        const orderRef = db
          .collection("orders")
          .doc(orderSnap.id);

        await orderRef.update({
          paymentStatus:
            "failed",

          xenditPaymentId:
            data.payment_id ||
            null,

          xenditPaymentRequestId:
            data.payment_request_id ||
            null,

          xenditReferenceId:
            data.reference_id ||
            null,

          xenditPaymentChannel:
            data.channel_code ||
            "GCASH",

          xenditPaymentStatus:
            data.status ||
            "FAILED",

          paymentFailureCode:
            data.failure_code ||
            null,

          paymentFailureReason:
            data.failure_reason ||
            null,

          fulfillmentStatus:
            "pending",

          updatedAt:
            FieldValue.serverTimestamp(),
        });

        console.log(
          `Payment failure saved for order ${orderSnap.id}`
        );

        return res.status(200).json({
          success: true,
          message:
            "Payment failure recorded.",
        });
      }

      /* ---------------------------------------------------
         ONLY payment.capture FULFILLS
      --------------------------------------------------- */

      if (
        event !==
        "payment.capture"
      ) {
        return res.status(200).json({
          success: true,
          message:
            "Webhook acknowledged; no fulfillment required.",
        });
      }

      /* ---------------------------------------------------
         STATUS CHECK
      --------------------------------------------------- */

      if (
        data.status &&
        data.status !==
          "SUCCEEDED"
      ) {
        console.error(
          "Unexpected payment.capture status:",
          data.status
        );

        return res.status(400).json({
          success: false,
          error:
            "Unexpected payment status.",
        });
      }

      /* ---------------------------------------------------
         CHANNEL CHECK
      --------------------------------------------------- */

      if (
        data.channel_code &&
        data.channel_code !==
          "GCASH"
      ) {
        console.error(
          "Unexpected payment channel:",
          data.channel_code
        );

        return res.status(400).json({
          success: false,
          error:
            "Unexpected payment channel.",
        });
      }

      /* ---------------------------------------------------
         FIND ORDER
      --------------------------------------------------- */

      const orderSnap =
        await findOrderFromWebhook(
          data
        );

      if (!orderSnap) {
        console.error(
          "ORDER NOT FOUND FOR PAYMENT CAPTURE:",
          {
            paymentId:
              data.payment_id,
            paymentRequestId:
              data.payment_request_id,
            referenceId:
              data.reference_id,
          }
        );

        return res.status(200).json({
          success: true,
          message:
            "Webhook acknowledged; order not found.",
        });
      }

      const orderRef = db
        .collection("orders")
        .doc(orderSnap.id);

      const order =
        orderSnap.data();

      /* ---------------------------------------------------
         PAYMENT REQUEST MATCH
      --------------------------------------------------- */

      if (
        order.xenditPaymentRequestId &&
        data.payment_request_id &&
        order.xenditPaymentRequestId !==
          data.payment_request_id
      ) {
        console.error(
          "PAYMENT REQUEST ID MISMATCH."
        );

        return res.status(400).json({
          success: false,
          error:
            "Payment request ID mismatch.",
        });
      }

      /* ---------------------------------------------------
         REFERENCE MATCH
      --------------------------------------------------- */

      if (
        order.xenditReferenceId &&
        data.reference_id &&
        order.xenditReferenceId !==
          data.reference_id
      ) {
        console.error(
          "XENDIT REFERENCE ID MISMATCH."
        );

        return res.status(400).json({
          success: false,
          error:
            "Payment reference mismatch.",
        });
      }

      /* ---------------------------------------------------
         AMOUNT CHECK
      --------------------------------------------------- */

      const orderTotal =
        Number(order.total);

      const capturedAmount = Number(
        data.captures?.[0]
          ?.capture_amount ??
          data.request_amount
      );

      if (
        !Number.isFinite(orderTotal) ||
        !Number.isFinite(capturedAmount)
      ) {
        console.error(
          "INVALID PAYMENT AMOUNT."
        );

        return res.status(400).json({
          success: false,
          error:
            "Invalid payment amount.",
        });
      }

      if (
        Math.abs(
          orderTotal -
            capturedAmount
        ) > 0.01
      ) {
        console.error(
          "PAYMENT AMOUNT MISMATCH:",
          {
            orderTotal,
            capturedAmount,
          }
        );

        return res.status(400).json({
          success: false,
          error:
            "Payment amount does not match order total.",
        });
      }

      /* ---------------------------------------------------
         CANCELLED ORDER
      --------------------------------------------------- */

      if (
        order.status ===
        "cancelled"
      ) {
        await orderRef.update({
          paymentStatus: "paid",

          xenditPaymentId:
            data.payment_id ||
            null,

          xenditPaymentRequestId:
            data.payment_request_id ||
            null,

          xenditReferenceId:
            data.reference_id ||
            null,

          xenditPaymentChannel:
            data.channel_code ||
            "GCASH",

          xenditPaymentStatus:
            data.status ||
            "SUCCEEDED",

          paidAt:
            FieldValue.serverTimestamp(),

          inventoryFulfilled: false,

          fulfillmentStatus:
            "manual_review",

          fulfillmentError:
            "Payment received after the order was cancelled.",

          xenditWebhookEvent:
            "payment.capture",

          xenditWebhookReceivedAt:
            FieldValue.serverTimestamp(),

          updatedAt:
            FieldValue.serverTimestamp(),
        });

        console.warn(
          `Cancelled order ${orderSnap.id} received payment. Manual review required.`
        );

        return res.status(200).json({
          success: true,
          message:
            "Payment received for cancelled order; manual review required.",
        });
      }

      /* ---------------------------------------------------
         SERVER-SIDE FIFO FULFILLMENT
      --------------------------------------------------- */

      try {
        const result =
          await fulfillPaidOrder(
            orderRef,
            data
          );

        console.log(
          "PAYMENT + FULFILLMENT COMPLETE:",
          {
            orderId:
              orderSnap.id,

            alreadyFulfilled:
              result.alreadyFulfilled,
          }
        );

        return res.status(200).json({
          success: true,

          message:
            result.alreadyFulfilled
              ? "Order already fulfilled."
              : "Payment captured and inventory fulfilled.",

          orderId:
            orderSnap.id,

          inventoryFulfilled: true,

          alreadyFulfilled:
            result.alreadyFulfilled,
        });
      } catch (
        fulfillmentError
      ) {
        /* -------------------------------------------------
           PAYMENT SUCCEEDED BUT STOCK FAILED
        ------------------------------------------------- */

        if (
          fulfillmentError.code ===
          "STOCK_UNAVAILABLE"
        ) {
          await orderRef.update({
            paymentStatus: "paid",

            xenditPaymentId:
              data.payment_id ||
              null,

            xenditPaymentRequestId:
              data.payment_request_id ||
              null,

            xenditReferenceId:
              data.reference_id ||
              null,

            xenditPaymentChannel:
              data.channel_code ||
              "GCASH",

            xenditPaymentStatus:
              data.status ||
              "SUCCEEDED",

            paidAt:
              FieldValue.serverTimestamp(),

            inventoryFulfilled: false,

            fulfillmentStatus:
              "stock_unavailable",

            fulfillmentError:
              fulfillmentError.message,

            xenditWebhookEvent:
              "payment.capture",

            xenditWebhookReceivedAt:
              FieldValue.serverTimestamp(),

            updatedAt:
              FieldValue.serverTimestamp(),
          });

          console.error(
            "PAYMENT SUCCESS BUT STOCK FULFILLMENT FAILED:",
            fulfillmentError.message
          );

          return res.status(200).json({
            success: true,
            message:
              "Payment received but inventory requires manual review.",
            orderId:
              orderSnap.id,
          });
        }

        throw fulfillmentError;
      }
    } catch (error) {
      console.error(
        "XENDIT WEBHOOK ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        error:
          error.message ||
          "Webhook processing failed.",
      });
    }
  }
);

/* =========================================================
   PAYMENT SUCCESS PAGE
========================================================= */

app.get(
  "/payment/success",
  (req, res) => {
    const orderId = String(
      req.query.orderId || ""
    );

    res.status(200).send(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
  />
  <title>FarmGate Payment</title>
</head>
<body
  style="
    font-family: Arial, sans-serif;
    text-align: center;
    padding: 40px;
  "
>
  <h2>Payment Submitted</h2>

  <p>
    Your GCash payment has been submitted.
  </p>

  <p>
    FarmGate is waiting for the final payment confirmation.
  </p>

  <p>
    Order ID:
    <strong>${orderId}</strong>
  </p>

  <p>
    You can return to the FarmGate app.
  </p>
</body>
</html>
    `);
  }
);

/* =========================================================
   PAYMENT FAILURE PAGE
========================================================= */

app.get(
  "/payment/failure",
  (req, res) => {
    const orderId = String(
      req.query.orderId || ""
    );

    res.status(200).send(`
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
  />
  <title>FarmGate Payment Failed</title>
</head>
<body
  style="
    font-family: Arial, sans-serif;
    text-align: center;
    padding: 40px;
  "
>
  <h2>Payment Failed</h2>

  <p>
    The GCash payment was not completed.
  </p>

  <p>
    Order ID:
    <strong>${orderId}</strong>
  </p>

  <p>
    Return to FarmGate and try again.
  </p>
</body>
</html>
    `);
  }
);

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

app.use(
  (error, req, res, next) => {
    console.error(
      "GLOBAL ERROR:",
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    return res.status(500).json({
      success: false,
      error:
        error.message ||
        "Internal server error.",
    });
  }
);

/* =========================================================
   START SERVER
========================================================= */

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(
    `FarmGate Backend running on port ${PORT}`
  );
});