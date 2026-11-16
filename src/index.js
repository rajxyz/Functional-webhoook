
/*
====================================================
TOOLGRAM - MAIN BACKEND
Payment + Premium Subscription API
Premium: Rs. 19 / 30 days

TEMPORARY DEBUGGING ENABLED
====================================================
*/

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const admin = require("firebase-admin");
const Razorpay = require("razorpay");

// ==================================================
// 1. ENVIRONMENT VARIABLES
// ==================================================

const REQUIRED_ENV = [
  "FIREBASE_PROJECT_ID",
  "FIREBASE_PRIVATE_KEY",
  "FIREBASE_CLIENT_EMAIL",
  "RAZORPAY_KEY_ID",
  "RAZORPAY_SECRET",
  "RAZORPAY_WEBHOOK_SECRET",
  "ALLOWED_ORIGINS",
];

for (const key of REQUIRED_ENV) {
  if (!process.env[key] || !process.env[key].trim()) {
    console.error(`[STARTUP ERROR] Missing environment variable: ${key}`);
    throw new Error(`Missing environment variable: ${key}`);
  }
}

const PORT = process.env.PORT || 3000;
const PREMIUM_AMOUNT = 1900;
const PREMIUM_CURRENCY = "INR";
const SUBSCRIPTION_DAYS = 30;

const allowedOrigins = process.env.ALLOWED_ORIGINS
  .split(",")
  .map((origin) => origin.trim().replace(/\/$/, ""))
  .filter(Boolean);

// ==================================================
// 2. FIREBASE ADMIN INITIALIZATION
// ==================================================

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }),
  });
}

const db = admin.firestore();
const Timestamp = admin.firestore.Timestamp;

// ==================================================
// 3. RAZORPAY INITIALIZATION
// ==================================================

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_SECRET,
});

// ==================================================
// 4. EXPRESS APP
// ==================================================

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);

// ==================================================
// 5. DEBUGGING MIDDLEWARE
// IMPORTANT: Keep this BEFORE CORS and other routes.
// ==================================================

app.use((req, res, next) => {
  const requestId = crypto.randomUUID
    ? crypto.randomUUID()
    : crypto.randomBytes(8).toString("hex");

  req.requestId = requestId;
  req.requestStartedAt = Date.now();

  console.log("\n========== INCOMING REQUEST ==========");
  console.log("Request ID:", requestId);
  console.log("Time:", new Date().toISOString());
  console.log("Method:", req.method);
  console.log("URL:", req.originalUrl);
  console.log("Origin:", req.headers.origin || "NO ORIGIN");
  console.log("IP:", req.ip);
  console.log("User Agent:", req.headers["user-agent"] || "UNKNOWN");

  // Never log Authorization headers, tokens or payment secrets.
  res.setHeader("X-Debug-Request-ID", requestId);

  res.on("finish", () => {
    console.log("========== REQUEST COMPLETED ==========");
    console.log("Request ID:", requestId);
    console.log("Method:", req.method);
    console.log("URL:", req.originalUrl);
    console.log("Status:", res.statusCode);
    console.log("Duration:", `${Date.now() - req.requestStartedAt}ms`);
    console.log("=======================================\n");
  });

  res.on("close", () => {
    if (!res.writableEnded) {
      console.error("[REQUEST ABORTED]", {
        requestId,
        method: req.method,
        url: req.originalUrl,
      });
    }
  });

  next();
});

// ==================================================
// 6. CORS
// ==================================================

const corsOptions = {
  origin(origin, callback) {
    if (!origin) {
      console.log("[CORS] Request has no Origin header.");
      return callback(null, true);
    }

    const normalizedOrigin = origin.replace(/\/$/, "");

    if (allowedOrigins.includes(normalizedOrigin)) {
      console.log("[CORS ALLOWED]", normalizedOrigin);
      return callback(null, true);
    }

    console.error("[CORS REJECTED]", {
      receivedOrigin: normalizedOrigin,
      allowedOrigins,
    });

    return callback(new Error("Origin not allowed by CORS"));
  },

  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// ==================================================
// 7. JSON BODY PARSER
// ==================================================

app.use(
  express.json({
    limit: "1mb",
    verify: (req, res, buffer) => {
      req.rawBody = Buffer.from(buffer);
    },
  })
);

// ==================================================
// 8. RATE LIMITING
// ==================================================

const paymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many payment requests. Please try again later.",
  },
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many requests. Please try again later.",
  },
});

// ==================================================
// 9. SECURITY HELPERS
// ==================================================

function safeCompare(value1, value2) {
  if (
    typeof value1 !== "string" ||
    typeof value2 !== "string" ||
    !value1 ||
    !value2
  ) {
    return false;
  }

  const a = Buffer.from(value1, "utf8");
  const b = Buffer.from(value2, "utf8");

  if (a.length !== b.length) return false;

  return crypto.timingSafeEqual(a, b);
}

function verifyPaymentSignature(orderId, paymentId, signature) {
  const expectedSignature = crypto
    .createHmac("sha256", process.env.RAZORPAY_SECRET)
    .update(`${orderId}|${paymentId}`)
    .digest("hex");

  return safeCompare(expectedSignature, signature);
}

function verifyWebhookSignature(req) {
  if (!req.rawBody) return false;

  const receivedSignature = req.headers["x-razorpay-signature"];
  if (!receivedSignature) return false;

  const expectedSignature = crypto
    .createHmac("sha256", process.env.RAZORPAY_WEBHOOK_SECRET)
    .update(req.rawBody)
    .digest("hex");

  return safeCompare(expectedSignature, receivedSignature);
}

// ==================================================
// 10. FIREBASE AUTHENTICATION
// ==================================================

async function authenticateUser(req, res, next) {
  try {
    console.log("[AUTH] Verifying Firebase token. Request:", req.requestId);

    const authHeader = req.headers.authorization || "";

    if (!authHeader.startsWith("Bearer ")) {
      console.warn("[AUTH FAILED] Missing Bearer token:", req.requestId);

      return res.status(401).json({
        success: false,
        message: "Authentication required. Please log in.",
      });
    }

    const idToken = authHeader.slice(7).trim();

    if (!idToken) {
      console.warn("[AUTH FAILED] Empty token:", req.requestId);

      return res.status(401).json({
        success: false,
        message: "Invalid authentication token.",
      });
    }

    const decodedToken = await admin.auth().verifyIdToken(idToken);

    req.user = {
      uid: decodedToken.uid,
      email: decodedToken.email || null,
    };

    console.log("[AUTH SUCCESS]", {
      requestId: req.requestId,
      uid: req.user.uid,
    });

    return next();
  } catch (error) {
    console.error("[AUTH ERROR]", {
      requestId: req.requestId,
      code: error.code || null,
      message: error.message,
    });

    return res.status(401).json({
      success: false,
      message: "Session expired or invalid. Please log in again.",
    });
  }
}

// ==================================================
// 11. SUBSCRIPTION STATUS
// ==================================================

async function getSubscription(uid) {
  console.log("[FIRESTORE] Reading subscription:", uid);

  const subscriptionRef = db.collection("subscriptions").doc(uid);
  const snapshot = await subscriptionRef.get();

  if (!snapshot.exists) {
    console.log("[FIRESTORE] No subscription found:", uid);

    return {
      premium: false,
      status: "free",
      expiryDate: null,
    };
  }

  const data = snapshot.data();
  const expiry = data.expiry_date;

  const validExpiry =
    expiry &&
    typeof expiry.toMillis === "function" &&
    expiry.toMillis() > Date.now();

  const isPremium = data.premium === true && validExpiry;

  const result = {
    premium: isPremium,
    status: isPremium
      ? "premium"
      : data.premium === true
        ? "expired"
        : "free",
    expiryDate:
      expiry && typeof expiry.toDate === "function"
        ? expiry.toDate().toISOString()
        : null,
  };

  console.log("[FIRESTORE] Subscription result:", {
    uid,
    status: result.status,
    premium: result.premium,
  });

  return result;
}

async function requirePremium(req, res, next) {
  try {
    const subscription = await getSubscription(req.user.uid);

    if (!subscription.premium) {
      console.warn("[PREMIUM DENIED]", {
        requestId: req.requestId,
        uid: req.user.uid,
        status: subscription.status,
      });

      return res.status(403).json({
        success: false,
        premium: false,
        status: subscription.status,
        message: "Premium subscription required.",
      });
    }

    req.subscription = subscription;
    return next();
  } catch (error) {
    console.error("[SUBSCRIPTION CHECK ERROR]", {
      requestId: req.requestId,
      message: error.message,
      stack: error.stack,
    });

    return res.status(500).json({
      success: false,
      message: "Unable to verify subscription.",
    });
  }
}

// ==================================================
// 12. ACTIVATE / RENEW SUBSCRIPTION
// ==================================================

async function activateSubscription({
  uid,
  paymentId,
  orderId,
  amount,
  currency,
}) {
  console.log("[SUBSCRIPTION] Activation started:", {
    uid,
    paymentId,
    orderId,
    amount,
    currency,
  });

  const paymentRef = db.collection("processedPayments").doc(paymentId);
  const subscriptionRef = db.collection("subscriptions").doc(uid);
  const orderRef = db.collection("paymentOrders").doc(orderId);

  return db.runTransaction(async (transaction) => {
    const [paymentSnapshot, subscriptionSnapshot, orderSnapshot] =
      await Promise.all([
        transaction.get(paymentRef),
        transaction.get(subscriptionRef),
        transaction.get(orderRef),
      ]);

    if (paymentSnapshot.exists) {
      const previousPayment = paymentSnapshot.data();

      if (
        previousPayment.uid !== uid ||
        previousPayment.orderId !== orderId
      ) {
        throw new Error("Payment already processed for another order.");
      }

      const existingSubscription = subscriptionSnapshot.exists
        ? subscriptionSnapshot.data()
        : {};

      console.log("[SUBSCRIPTION] Duplicate payment; already processed.");

      return {
        alreadyProcessed: true,
        expiryDate: existingSubscription.expiry_date || null,
      };
    }

    if (!orderSnapshot.exists) {
      throw new Error("Payment order not found.");
    }

    const orderData = orderSnapshot.data();

    if (orderData.userId !== uid) {
      throw new Error("Payment order does not belong to this user.");
    }

    if (
      orderData.amount !== amount ||
      orderData.currency !== currency ||
      amount !== PREMIUM_AMOUNT ||
      currency !== PREMIUM_CURRENCY
    ) {
      throw new Error("Payment amount or currency mismatch.");
    }

    if (orderData.status !== "created") {
      throw new Error("Payment order is not available for activation.");
    }

    const now = Timestamp.now();

    const existingData = subscriptionSnapshot.exists
      ? subscriptionSnapshot.data()
      : {};

    const existingExpiry = existingData.expiry_date;

    const existingPlanActive =
      existingData.premium === true &&
      existingExpiry &&
      typeof existingExpiry.toMillis === "function" &&
      existingExpiry.toMillis() > now.toMillis();

    const startDate = existingPlanActive
      ? existingExpiry.toDate()
      : now.toDate();

    const newExpiryDate = new Date(
      startDate.getTime() + SUBSCRIPTION_DAYS * 24 * 60 * 60 * 1000
    );

    const newExpiryTimestamp = Timestamp.fromDate(newExpiryDate);

    transaction.set(
      subscriptionRef,
      {
        uid,
        premium: true,
        expiry_date: newExpiryTimestamp,
        updated_at: now,
        last_payment_id: paymentId,
        last_order_id: orderId,
      },
      { merge: true }
    );

    transaction.create(paymentRef, {
      uid,
      paymentId,
      orderId,
      amount,
      currency,
      status: "paid",
      created_at: now,
    });

    transaction.set(
      orderRef,
      {
        status: "paid",
        paymentId,
        paid_at: now,
      },
      { merge: true }
    );

    console.log("[SUBSCRIPTION] Activation transaction prepared:", {
      uid,
      newExpiryDate: newExpiryDate.toISOString(),
    });

    return {
      alreadyProcessed: false,
      expiryDate: newExpiryTimestamp,
    };
  });
}

// ==================================================
// 13. CREATE RAZORPAY ORDER
// ==================================================

app.post(
  "/create-order",
  paymentLimiter,
  authenticateUser,
  async (req, res) => {
    try {
      console.log("[CREATE ORDER] Started:", req.requestId);

      const uid = req.user.uid;

      const order = await razorpay.orders.create({
        amount: PREMIUM_AMOUNT,
        currency: PREMIUM_CURRENCY,
        receipt: `tg_${uid.slice(0, 12)}_${Date.now()}`,
        notes: {
          userId: uid,
          plan: "Toolgram Premium",
          duration: "30 days",
        },
      });

      await db.collection("paymentOrders").doc(order.id).set({
        userId: uid,
        orderId: order.id,
        amount: PREMIUM_AMOUNT,
        currency: PREMIUM_CURRENCY,
        status: "created",
        created_at: Timestamp.now(),
      });

      console.log("[CREATE ORDER SUCCESS]", {
        requestId: req.requestId,
        orderId: order.id,
      });

      return res.json({
        success: true,
        orderId: order.id,
        amount: PREMIUM_AMOUNT,
        currency: PREMIUM_CURRENCY,
        keyId: process.env.RAZORPAY_KEY_ID,
      });
    } catch (error) {
      console.error("[CREATE ORDER ERROR]", {
        requestId: req.requestId,
        message: error.message,
        statusCode: error.statusCode || null,
        errorCode: error.error?.code || null,
      });

      return res.status(500).json({
        success: false,
        message: "Unable to create payment order.",
      });
    }
  }
);

// ==================================================
// 14. VERIFY RAZORPAY PAYMENT
// ==================================================

app.post(
  "/verify-payment",
  paymentLimiter,
  authenticateUser,
  async (req, res) => {
    try {
      console.log("[VERIFY PAYMENT] Started:", req.requestId);

      const {
        razorpay_order_id: orderId,
        razorpay_payment_id: paymentId,
        razorpay_signature: signature,
      } = req.body || {};

      if (!orderId || !paymentId || !signature) {
        return res.status(400).json({
          success: false,
          message: "Missing payment verification details.",
        });
      }

      if (!verifyPaymentSignature(orderId, paymentId, signature)) {
        console.warn("[VERIFY PAYMENT] Invalid signature:", req.requestId);

        return res.status(400).json({
          success: false,
          message: "Invalid payment signature.",
        });
      }

      const orderSnapshot = await db
        .collection("paymentOrders")
        .doc(orderId)
        .get();

      if (!orderSnapshot.exists) {
        return res.status(404).json({
          success: false,
          message: "Payment order not found.",
        });
      }

      const orderData = orderSnapshot.data();

      if (orderData.userId !== req.user.uid) {
        return res.status(403).json({
          success: false,
          message: "This payment order does not belong to you.",
        });
      }

      const payment = await razorpay.payments.fetch(paymentId);

      if (
        payment.order_id !== orderId ||
        payment.status !== "captured" ||
        payment.amount !== PREMIUM_AMOUNT ||
        payment.currency !== PREMIUM_CURRENCY
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Payment is not captured or payment details do not match.",
        });
      }

      await activateSubscription({
        uid: req.user.uid,
        paymentId,
        orderId,
        amount: payment.amount,
        currency: payment.currency,
      });

      const subscription = await getSubscription(req.user.uid);

      console.log("[VERIFY PAYMENT SUCCESS]", req.requestId);

      return res.json({
        success: true,
        premium: subscription.premium,
        status: subscription.status,
        expiryDate: subscription.expiryDate,
        message: "Premium subscription activated successfully.",
      });
    } catch (error) {
      console.error("[PAYMENT VERIFICATION ERROR]", {
        requestId: req.requestId,
        message: error.message,
        stack: error.stack,
        razorpayCode: error.error?.code || null,
      });

      return res.status(500).json({
        success: false,
        message:
          "Payment verification failed. Please contact support if money was deducted.",
      });
    }
  }
);


// ==================================================
// 15. RAZORPAY WEBHOOK
// ==================================================

app.post("/razorpay-webhook", async (req, res) => {
  try {
    console.log("[WEBHOOK] Request received:", req.requestId);

    if (!verifyWebhookSignature(req)) {
      console.error("[WEBHOOK] Invalid signature:", req.requestId);
      return res.status(400).send("Invalid webhook signature");
    }

    const event = req.body;

    console.log("[WEBHOOK] Event:", event.event);

    if (event.event !== "payment.captured") {
      return res.status(200).json({
        received: true,
        ignored: true,
      });
    }

    const payment = event.payload?.payment?.entity;

    if (!payment) {
      return res.status(400).send("Payment data missing");
    }

    const paymentId = payment.id;
    const orderId = payment.order_id;

    if (!paymentId || !orderId) {
      return res.status(400).send("Required payment details missing");
    }

    if (
      payment.status !== "captured" ||
      payment.amount !== PREMIUM_AMOUNT ||
      payment.currency !== PREMIUM_CURRENCY
    ) {
      return res.status(400).send("Payment details do not match");
    }

    const orderSnapshot = await db
      .collection("paymentOrders")
      .doc(orderId)
      .get();

    if (!orderSnapshot.exists) {
      return res.status(404).send("Payment order not found");
    }

    const orderData = orderSnapshot.data();
    const uid = orderData.userId;

    if (!uid) {
      return res.status(400).send("Order user not found");
    }

    if (payment.notes?.userId && payment.notes.userId !== uid) {
      return res.status(400).send("Payment user mismatch");
    }

    if (
      orderData.amount !== PREMIUM_AMOUNT ||
      orderData.currency !== PREMIUM_CURRENCY ||
      payment.order_id !== orderData.orderId
    ) {
      return res.status(400).send("Order ownership or amount mismatch");
    }

    await activateSubscription({
      uid,
      paymentId,
      orderId,
      amount: payment.amount,
      currency: payment.currency,
    });

    console.log("[WEBHOOK SUCCESS]", {
      requestId: req.requestId,
      orderId,
      paymentId,
    });

    return res.status(200).json({
      received: true,
      success: true,
    });
  } catch (error) {
    console.error("[WEBHOOK ERROR]", {
      requestId: req.requestId,
      message: error.message,
      stack: error.stack,
    });

    return res.status(500).send("Webhook processing failed");
  }
});

// ==================================================
// 16. SUBSCRIPTION STATUS API
// ==================================================

app.get(
  "/subscription-status",
  apiLimiter,
  authenticateUser,
  async (req, res) => {
    try {
      console.log("[STATUS API] Started:", req.requestId);

      const subscription = await getSubscription(req.user.uid);

      console.log("[STATUS API SUCCESS]", {
        requestId: req.requestId,
        status: subscription.status,
      });

      return res.json({
        success: true,
        premium: subscription.premium,
        status: subscription.status,
        expiryDate: subscription.expiryDate,
      });
    } catch (error) {
      console.error("[STATUS API ERROR]", {
        requestId: req.requestId,
        message: error.message,
        stack: error.stack,
      });

      return res.status(500).json({
        success: false,
        message: "Unable to fetch subscription status.",
      });
    }
  }
);

// ==================================================
// 17. PROTECTED AI ENDPOINT PLACEHOLDER
// ==================================================

app.post(
  "/ai-request",
  apiLimiter,
  authenticateUser,
  requirePremium,
  async (req, res) => {
    return res.status(501).json({
      success: false,
      message: "AI request functionality has not been connected yet.",
    });
  }
);

// ==================================================
// 18. HEALTH CHECK
// ==================================================

app.get("/", (req, res) => {
  console.log("[HEALTH] Root endpoint accessed:", req.requestId);

  return res.status(200).json({
    success: true,
    service: "Toolgram Main Backend",
    status: "running",
    requestId: req.requestId,
  });
});

app.get("/healthz", (req, res) => {
  console.log("[HEALTH] Health endpoint accessed:", req.requestId);

  return res.status(200).json({
    success: true,
    service: "Toolgram Main Backend",
    status: "running",
    requestId: req.requestId,
    timestamp: new Date().toISOString(),
  });
});

// ==================================================
// 19. NOT FOUND HANDLER
// ==================================================

app.use((req, res) => {
  console.warn("[404 NOT FOUND]", {
    requestId: req.requestId,
    method: req.method,
    url: req.originalUrl,
  });

  return res.status(404).json({
    success: false,
    message: "API route not found.",
    path: req.originalUrl,
    requestId: req.requestId,
  });
});

// ==================================================
// 20. GLOBAL ERROR HANDLER
// Must remain AFTER all routes.
// ==================================================

app.use((error, req, res, next) => {
  console.error("\n========== GLOBAL BACKEND ERROR ==========");
  console.error("Request ID:", req.requestId || "UNKNOWN");
  console.error("Method:", req.method);
  console.error("URL:", req.originalUrl);
  console.error("Error name:", error.name);
  console.error("Error message:", error.message);
  console.error("Error stack:", error.stack);
  console.error("===========================================\n");

  if (res.headersSent) {
    return next(error);
  }

  if (error.message === "Origin not allowed by CORS") {
    return res.status(403).json({
      success: false,
      message: "This website origin is not allowed.",
      requestId: req.requestId,
    });
  }

  if (error instanceof SyntaxError && error.status === 400 && "body" in error) {
    return res.status(400).json({
      success: false,
      message: "Invalid JSON request body.",
      requestId: req.requestId,
    });
  }

  return res.status(500).json({
    success: false,
    message: "Internal server error.",
    requestId: req.requestId,
  });
});

// ==================================================
// 21. PROCESS-LEVEL ERROR LOGGING
// ==================================================

process.on("unhandledRejection", (reason) => {
  console.error("[UNHANDLED PROMISE REJECTION]", reason);
});

process.on("uncaughtException", (error) => {
  console.error("[UNCAUGHT EXCEPTION]", error.stack || error.message);

  // Exit so Render can restart the process in a clean state.
  process.exit(1);
});

// ==================================================
// 22. START SERVER
// ==================================================

const server = app.listen(PORT, () => {
  console.log("\n============================================");
  console.log("TOOLGRAM BACKEND STARTED SUCCESSFULLY");
  console.log("Port:", PORT);
  console.log("Environment:", process.env.NODE_ENV || "not specified");
  console.log("Allowed Origins:", allowedOrigins);
  console.log("Debug Logging: ENABLED");
  console.log("Health URL: /healthz");
  console.log("============================================\n");
});

server.on("error", (error) => {
  console.error("[SERVER START ERROR]", error);
});

