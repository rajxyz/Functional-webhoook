// ============================================
// TOOLGRAM - MAIN BACKEND
// Payment + Premium Subscription API
// Premium: ₹19 / 30 days
// DEBUG VERSION 2.0
// ============================================

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const admin = require("firebase-admin");
const Razorpay = require("razorpay");

// ============================================
// 1. ENVIRONMENT VARIABLES
// ============================================

const REQUIRED_ENV = [
  "FIREBASE_PROJECT_ID",
  "FIREBASE_PRIVATE_KEY",
  "FIREBASE_CLIENT_EMAIL",
  "RAZORPAY_KEY_ID",
  "RAZORPAY_SECRET",
  "RAZORPAY_WEBHOOK_SECRET"
];

for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    throw new Error(`Missing environment variable: ${key}`);
  }
}

if (!process.env.ALLOWED_ORIGINS) {
  throw new Error("Missing environment variable: ALLOWED_ORIGINS");
}

const PORT = process.env.PORT || 3000;

const PREMIUM_AMOUNT = 1900;
const PREMIUM_CURRENCY = "INR";
const SUBSCRIPTION_DAYS = 30;

const allowedOrigins = process.env.ALLOWED_ORIGINS
  .split(",")
  .map(origin => origin.trim().replace(/\/$/, ""))
  .filter(Boolean);

// ============================================
// 2. FIREBASE INITIALIZATION
// ============================================

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n")
    })
  });
}

const db = admin.firestore();
const Timestamp = admin.firestore.Timestamp;

// ============================================
// 3. RAZORPAY INITIALIZATION
// ============================================

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_SECRET
});

// ============================================
// 4. EXPRESS + CORS
// ============================================

const app = express();

app.disable("x-powered-by");

app.use((req, res, next) => {
  console.log(
    `[REQUEST] ${new Date().toISOString()} ${req.method} ${req.originalUrl}`,
    "Origin:",
    req.headers.origin || "NO ORIGIN"
  );
  next();
});

const corsOptions = {
  origin(origin, callback) {
    if (!origin) {
      return callback(null, true);
    }

    const normalizedOrigin = origin.replace(/\/$/, "");

    if (allowedOrigins.includes(normalizedOrigin)) {
      return callback(null, true);
    }

    console.error("[CORS BLOCKED]", {
      receivedOrigin: origin,
      allowedOrigins
    });

    return callback(new Error("Origin not allowed by CORS"));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// Preserve raw body for Razorpay webhook signature.
app.use(express.json({
  limit: "1mb",
  verify(req, res, buffer) {
    req.rawBody = Buffer.from(buffer);
  }
}));

// ============================================
// 5. RATE LIMITING
// ============================================

const paymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    success: false,
    message: "Too many payment requests. Try later."
  }
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

// ============================================
// 6. SECURITY HELPERS
// ============================================

function safeCompare(value1, value2) {
  if (
    typeof value1 !== "string" ||
    typeof value2 !== "string" ||
    !value1 ||
    !value2
  ) return false;

  const a = Buffer.from(value1);
  const b = Buffer.from(value2);

  if (a.length !== b.length) return false;

  return crypto.timingSafeEqual(a, b);
}

function verifyPaymentSignature(orderId, paymentId, signature) {
  const expected = crypto
    .createHmac("sha256", process.env.RAZORPAY_SECRET)
    .update(`${orderId}|${paymentId}`)
    .digest("hex");

  return safeCompare(expected, signature);
}

function verifyWebhookSignature(req) {
  const signature = req.headers["x-razorpay-signature"];

  if (!req.rawBody || !signature) return false;

  const expected = crypto
    .createHmac("sha256", process.env.RAZORPAY_WEBHOOK_SECRET)
    .update(req.rawBody)
    .digest("hex");

  return safeCompare(expected, signature);
}

// ============================================
// 7. FIREBASE AUTHENTICATION
// ============================================

async function authenticateUser(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";

    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication required."
      });
    }

    const token = authHeader.slice(7).trim();

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Empty authentication token."
      });
    }

    const decoded = await admin.auth().verifyIdToken(token);

    req.user = {
      uid: decoded.uid,
      email: decoded.email || null
    };

    next();

  } catch (error) {
    console.error("[AUTH ERROR]", error);

    return res.status(401).json({
      success: false,
      message: "Invalid or expired Firebase session."
    });
  }
}

// ============================================
// 8. SUBSCRIPTION CHECK
// ============================================

async function getSubscription(uid) {
  const ref = db.collection("subscriptions").doc(uid);
  const snapshot = await ref.get();

  if (!snapshot.exists) {
    return {
      premium: false,
      status: "free",
      expiryDate: null
    };
  }

  const data = snapshot.data();
  const expiry = data.expiry_date;

  const validExpiry =
    expiry &&
    typeof expiry.toMillis === "function" &&
    expiry.toMillis() > Date.now();

  const premium = data.premium === true && validExpiry;

  return {
    premium,
    status: premium
      ? "premium"
      : data.premium === true
        ? "expired"
        : "free",
    expiryDate:
      expiry && typeof expiry.toDate === "function"
        ? expiry.toDate().toISOString()
        : null
  };
}

async function requirePremium(req, res, next) {
  try {
    const subscription = await getSubscription(req.user.uid);

    if (!subscription.premium) {
      return res.status(403).json({
        success: false,
        premium: false,
        status: subscription.status,
        message: "Premium subscription required."
      });
    }

    req.subscription = subscription;
    next();

  } catch (error) {
    console.error("[PREMIUM CHECK ERROR]", error);

    return res.status(500).json({
      success: false,
      message: "Unable to verify subscription."
    });
  }
}

// ============================================
// 9. ACTIVATE SUBSCRIPTION
// ============================================

async function activateSubscription({
  uid,
  paymentId,
  orderId,
  amount,
  currency
}) {
  const paymentRef = db.collection("processedPayments").doc(paymentId);
  const subscriptionRef = db.collection("subscriptions").doc(uid);
  const orderRef = db.collection("paymentOrders").doc(orderId);

  return db.runTransaction(async transaction => {
    const [
      paymentSnapshot,
      subscriptionSnapshot,
      orderSnapshot
    ] = await Promise.all([
      transaction.get(paymentRef),
      transaction.get(subscriptionRef),
      transaction.get(orderRef)
    ]);

    if (paymentSnapshot.exists) {
      const existing = subscriptionSnapshot.exists
        ? subscriptionSnapshot.data()
        : {};

      return {
        alreadyProcessed: true,
        expiryDate: existing.expiry_date || null
      };
    }

    if (!orderSnapshot.exists) {
      throw new Error("Payment order not found.");
    }

    const order = orderSnapshot.data();

    if (order.userId !== uid) {
      throw new Error("Payment order ownership mismatch.");
    }

    if (
      order.amount !== amount ||
      order.currency !== currency ||
      amount !== PREMIUM_AMOUNT ||
      currency !== PREMIUM_CURRENCY
    ) {
      throw new Error("Payment amount or currency mismatch.");
    }

    const now = Timestamp.now();

    const existing = subscriptionSnapshot.exists
      ? subscriptionSnapshot.data()
      : {};

    const oldExpiry = existing.expiry_date;

    const active =
      existing.premium === true &&
      oldExpiry &&
      typeof oldExpiry.toMillis === "function" &&
      oldExpiry.toMillis() > now.toMillis();

    const startDate = active
      ? oldExpiry.toDate()
      : now.toDate();

    const expiryDate = new Date(
      startDate.getTime() +
      SUBSCRIPTION_DAYS * 24 * 60 * 60 * 1000
    );

    const expiryTimestamp = Timestamp.fromDate(expiryDate);

    transaction.set(subscriptionRef, {
      uid,
      premium: true,
      expiry_date: expiryTimestamp,
      updated_at: now,
      last_payment_id: paymentId,
      last_order_id: orderId
    }, { merge: true });

    transaction.create(paymentRef, {
      uid,
      paymentId,
      orderId,
      amount,
      currency,
      status: "paid",
      created_at: now
    });

    transaction.set(orderRef, {
      status: "paid",
      paymentId,
      paid_at: now
    }, { merge: true });

    return {
      alreadyProcessed: false,
      expiryDate: expiryTimestamp
    };
  });
}

// ============================================
// 10. CREATE PAYMENT ORDER
// ============================================

app.post(
  "/create-order",
  paymentLimiter,
  authenticateUser,
  async (req, res) => {
    try {
      const uid = req.user.uid;

      const order = await razorpay.orders.create({
        amount: PREMIUM_AMOUNT,
        currency: PREMIUM_CURRENCY,
        receipt: `tg_${uid.slice(0, 12)}_${Date.now()}`,
        notes: {
          userId: uid,
          plan: "Toolgram Premium",
          duration: "30 days"
        }
      });

      await db.collection("paymentOrders").doc(order.id).set({
        userId: uid,
        orderId: order.id,
        amount: PREMIUM_AMOUNT,
        currency: PREMIUM_CURRENCY,
        status: "created",
        created_at: Timestamp.now()
      });

      return res.json({
        success: true,
        orderId: order.id,
        amount: PREMIUM_AMOUNT,
        currency: PREMIUM_CURRENCY,
        keyId: process.env.RAZORPAY_KEY_ID
      });

    } catch (error) {
      console.error("[CREATE ORDER ERROR]", error);

      return res.status(500).json({
        success: false,
        message: "Unable to create payment order."
      });
    }
  }
);

// ============================================
// 11. VERIFY PAYMENT
// ============================================

app.post(
  "/verify-payment",
  paymentLimiter,
  authenticateUser,
  async (req, res) => {
    try {
      const {
        razorpay_order_id: orderId,
        razorpay_payment_id: paymentId,
        razorpay_signature: signature
      } = req.body || {};

      if (!orderId || !paymentId || !signature) {
        return res.status(400).json({
          success: false,
          message: "Missing payment verification details."
        });
      }

      if (!verifyPaymentSignature(orderId, paymentId, signature)) {
        return res.status(400).json({
          success: false,
          message: "Invalid payment signature."
        });
      }

      const orderSnapshot = await db
        .collection("paymentOrders")
        .doc(orderId)
        .get();

      if (!orderSnapshot.exists) {
        return res.status(404).json({
          success: false,
          message: "Payment order not found."
        });
      }

      const orderData = orderSnapshot.data();

      if (orderData.userId !== req.user.uid) {
        return res.status(403).json({
          success: false,
          message: "Payment order ownership mismatch."
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
          message: "Payment details do not match."
        });
      }

      await activateSubscription({
        uid: req.user.uid,
        paymentId,
        orderId,
        amount: payment.amount,
        currency: payment.currency
      });

      const subscription = await getSubscription(req.user.uid);

      return res.json({
        success: true,
        premium: subscription.premium,
        status: subscription.status,
        expiryDate: subscription.expiryDate,
        message: "Premium activated successfully."
      });

    } catch (error) {
      console.error("[VERIFY PAYMENT ERROR]", error);

      return res.status(500).json({
        success: false,
        message: "Payment verification failed."
      });
    }
  }
);

// ============================================
// 12. RAZORPAY WEBHOOK
// ============================================

app.post("/razorpay-webhook", async (req, res) => {
  try {
    if (!verifyWebhookSignature(req)) {
      return res.status(400).send("Invalid webhook signature");
    }

    const event = req.body;

    if (event.event !== "payment.captured") {
      return res.status(200).json({
        received: true,
        ignored: true
      });
    }

    const payment = event.payload?.payment?.entity;

    if (!payment) {
      return res.status(400).send("Payment data missing");
    }

    const paymentId = payment.id;
    const orderId = payment.order_id;
    const uid = payment.notes?.userId;

    if (!paymentId || !orderId || !uid) {
      return res.status(400).send("Payment details missing");
    }

    if (
      payment.status !== "captured" ||
      payment.amount !== PREMIUM_AMOUNT ||
      payment.currency !== PREMIUM_CURRENCY
    ) {
      return res.status(400).send("Payment details mismatch");
    }

    const orderSnapshot = await db
      .collection("paymentOrders")
      .doc(orderId)
      .get();

    if (!orderSnapshot.exists) {
      return res.status(404).send("Payment order not found");
    }

    const order = orderSnapshot.data();

    if (
      order.userId !== uid ||
      order.amount !== PREMIUM_AMOUNT ||
      order.currency !== PREMIUM_CURRENCY
    ) {
      return res.status(400).send("Order mismatch");
    }

    await activateSubscription({
      uid,
      paymentId,
      orderId,
      amount: payment.amount,
      currency: payment.currency
    });

    return res.status(200).json({
      received: true,
      success: true
    });

  } catch (error) {
    console.error("[WEBHOOK ERROR]", error);
    return res.status(500).send("Webhook processing failed");
  }
});

// ============================================
// 13. SUBSCRIPTION STATUS
// ============================================

app.get(
  "/subscription-status",
  apiLimiter,
  authenticateUser,
  async (req, res) => {
    try {
      const subscription = await getSubscription(req.user.uid);

      return res.json({
        success: true,
        premium: subscription.premium,
        status: subscription.status,
        expiryDate: subscription.expiryDate
      });

    } catch (error) {
      console.error("[SUBSCRIPTION STATUS ERROR]", error);

      return res.status(500).json({
        success: false,
        message: "Unable to fetch subscription status."
      });
    }
  }
);

// ============================================
// 14. PROTECTED AI API
// ============================================

app.post(
  "/ai-request",
  apiLimiter,
  authenticateUser,
  requirePremium,
  async (req, res) => {
    return res.status(501).json({
      success: false,
      message: "AI functionality is not connected yet."
    });
  }
);

// ============================================
// 15. ROOT DIAGNOSTIC ROUTE
// ============================================

app.get("/", (req, res) => {
  return res.status(200).json({
    success: true,
    message: "TOOLGRAM ROOT INDEX IS RUNNING",
    service: "Toolgram Main Backend",
    version: "DEBUG-2026-11-15",
    timestamp: new Date().toISOString()
  });
});

// ============================================
// 16. HEALTH CHECK
// ============================================

app.get("/healthz", (req, res) => {
  return res.status(200).json({
    success: true,
    service: "Toolgram Main Backend",
    status: "running",
    timestamp: new Date().toISOString()
  });
});

// ============================================
// 17. CORS DIAGNOSTIC
// ============================================

app.get("/debug/cors", (req, res) => {
  const origin = req.headers.origin || null;

  return res.json({
    success: true,
    receivedOrigin: origin,
    allowedOrigins,
    originAllowed: !origin ||
      allowedOrigins.includes(origin.replace(/\/$/, ""))
  });
});

// ============================================
// 18. ROUTE DIAGNOSTIC
// ============================================

app.get("/debug/routes", (req, res) => {
  return res.json({
    success: true,
    service: "Toolgram Main Backend",
    routes: [
      "GET /",
      "GET /healthz",
      "GET /debug/cors",
      "GET /debug/routes",
      "GET /subscription-status",
      "POST /create-order",
      "POST /verify-payment",
      "POST /razorpay-webhook",
      "POST /ai-request"
    ]
  });
});

// ============================================
// 19. NOT FOUND HANDLER
// ============================================

app.use((req, res) => {
  console.error("[404 NOT FOUND]", {
    method: req.method,
    path: req.originalUrl,
    origin: req.headers.origin || null
  });

  return res.status(404).json({
    success: false,
    error: "ROUTE_NOT_FOUND",
    requestedPath: req.originalUrl,
    method: req.method,
    service: "TOOLGRAM ROOT INDEX"
  });
});

// ============================================
// 20. CORS + GLOBAL ERROR HANDLER
// ============================================

app.use((error, req, res, next) => {
  console.error("[GLOBAL ERROR]", {
    message: error.message,
    path: req.originalUrl,
    method: req.method
  });

  if (res.headersSent) {
    return next(error);
  }

  if (error.message === "Origin not allowed by CORS") {
    return res.status(403).json({
      success: false,
      error: "CORS_ORIGIN_BLOCKED",
      message: "This website origin is not allowed.",
      receivedOrigin: req.headers.origin || null,
      allowedOrigins
    });
  }

  return res.status(500).json({
    success: false,
    error: "INTERNAL_SERVER_ERROR",
    message: "Internal server error."
  });
});

// ============================================
// 21. START SERVER
// ============================================

app.listen(PORT, () => {
  console.log("====================================");
  console.log("TOOLGRAM BACKEND STARTED");
  console.log("====================================");
  console.log("Port:", PORT);
  console.log("Version: DEBUG-2026-11-15");
  console.log("Allowed Origins:", allowedOrigins);
  console.log("Root Directory Entry: index.js");
  console.log("Health Route: /healthz");
  console.log("====================================");
});
    
