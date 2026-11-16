
// ============================================
// TOOLGRAM - MAIN BACKEND
// Payment + Premium Subscription API
// Premium: Rs. 19 / 30 days
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
  "RAZORPAY_WEBHOOK_SECRET",
  "ALLOWED_ORIGINS",
];

for (const key of REQUIRED_ENV) {
  if (!process.env[key] || !process.env[key].trim()) {
    throw new Error(`Missing environment variable: ${key}`);
  }
}

const PORT = process.env.PORT || 3000;

const PREMIUM_AMOUNT = 1900; // Rs. 19 in paise
const PREMIUM_CURRENCY = "INR";
const SUBSCRIPTION_DAYS = 30;

// Example:
// ALLOWED_ORIGINS=https://toolgramm.vercel.app,https://frontendtoolgramtrick.vercel.app

const allowedOrigins = process.env.ALLOWED_ORIGINS
  .split(",")
  .map((origin) => origin.trim().replace(/\/$/, ""))
  .filter(Boolean);

// ============================================
// 2. FIREBASE ADMIN INITIALIZATION
// ============================================

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

// ============================================
// 3. RAZORPAY INITIALIZATION
// ============================================

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_SECRET,
});

// ============================================
// 4. EXPRESS APP + CORS
// ============================================

const app = express();

app.disable("x-powered-by");

// Render runs behind a reverse proxy.
app.set("trust proxy", 1);

const corsOptions = {
  origin(origin, callback) {
    // Allow requests without Origin, such as server-to-server requests.
    if (!origin) {
      return callback(null, true);
    }

    const normalizedOrigin = origin.replace(/\/$/, "");

    if (allowedOrigins.includes(normalizedOrigin)) {
      return callback(null, true);
    }

    return callback(new Error("Origin not allowed by CORS"));
  },

  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// Save raw body for Razorpay webhook signature verification.
app.use(
  express.json({
    limit: "1mb",
    verify: (req, res, buffer) => {
      req.rawBody = Buffer.from(buffer);
    },
  })
);

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

// ============================================
// 6. SECURITY HELPERS
// ============================================

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

  if (a.length !== b.length) {
    return false;
  }

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

// ============================================
// 7. FIREBASE AUTHENTICATION
// ============================================

async function authenticateUser(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";

    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication required. Please log in.",
      });
    }

    const idToken = authHeader.slice(7).trim();

    if (!idToken) {
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

    return next();
  } catch (error) {
    console.error("Authentication error:", error.message);

    return res.status(401).json({
      success: false,
      message: "Session expired or invalid. Please log in again.",
    });
  }
}

// ============================================
// 8. SUBSCRIPTION STATUS CHECK
// ============================================

async function getSubscription(uid) {
  const subscriptionRef = db.collection("subscriptions").doc(uid);
  const snapshot = await subscriptionRef.get();

  if (!snapshot.exists) {
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

  return {
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
}

async function requirePremium(req, res, next) {
  try {
    const subscription = await getSubscription(req.user.uid);

    if (!subscription.premium) {
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
    console.error("Subscription check error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to verify subscription.",
    });
  }
}

// ============================================
// 9. ACTIVATE / RENEW SUBSCRIPTION
// ============================================

async function activateSubscription({
  uid,
  paymentId,
  orderId,
  amount,
  currency,
}) {
  const paymentRef = db.collection("processedPayments").doc(paymentId);
  const subscriptionRef = db.collection("subscriptions").doc(uid);
  const orderRef = db.collection("paymentOrders").doc(orderId);

  return db.runTransaction(async (transaction) => {
    // All reads must happen before writes.
    const [paymentSnapshot, subscriptionSnapshot, orderSnapshot] =
      await Promise.all([
        transaction.get(paymentRef),
        transaction.get(subscriptionRef),
        transaction.get(orderRef),
      ]);

    // Check duplicate payment and verify its ownership.
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

    // Active plan: extend from existing expiry.
    // Expired/free plan: start from current time.
    const startDate = existingPlanActive
      ? existingExpiry.toDate()
      : now.toDate();

    const newExpiryDate = new Date(
      startDate.getTime() +
        SUBSCRIPTION_DAYS * 24 * 60 * 60 * 1000
    );

    const newExpiryTimestamp = Timestamp.fromDate(newExpiryDate);

    // All writes start after all reads.
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

    return {
      alreadyProcessed: false,
      expiryDate: newExpiryTimestamp,
    };
  });
}

// ============================================
// 10. CREATE RAZORPAY ORDER
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

      // Response fields are top-level.
      return res.json({
        success: true,
        orderId: order.id,
        amount: PREMIUM_AMOUNT,
        currency: PREMIUM_CURRENCY,
        keyId: process.env.RAZORPAY_KEY_ID,
      });
    } catch (error) {
      console.error("Create order error:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to create payment order.",
      });
    }
  }
);

// ============================================
// 11. VERIFY RAZORPAY PAYMENT
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
        razorpay_signature: signature,
      } = req.body || {};

      if (!orderId || !paymentId || !signature) {
        return res.status(400).json({
          success: false,
          message: "Missing payment verification details.",
        });
      }

      // Verify checkout signature.
      if (!verifyPaymentSignature(orderId, paymentId, signature)) {
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

      // Verify payment directly with Razorpay.
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

      return res.json({
        success: true,
        premium: subscription.premium,
        status: subscription.status,
        expiryDate: subscription.expiryDate,
        message: "Premium subscription activated successfully.",
      });
    } catch (error) {
      console.error("Payment verification error:", error);

      return res.status(500).json({
        success: false,
        message:
          "Payment verification failed. Please contact support if money was deducted.",
      });
    }
  }
);

// ============================================
// 12. RAZORPAY WEBHOOK
// ============================================

app.post("/razorpay-webhook", async (req, res) => {
  try {
    // Verify Razorpay webhook signature.
    if (!verifyWebhookSignature(req)) {
      return res.status(400).send("Invalid webhook signature");
    }

    const event = req.body;

    // Ignore events not handled by this backend.
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

    // Use our saved order record as the source of user ownership.
    const uid = orderData.userId;

    if (!uid) {
      return res.status(400).send("Order user not found");
    }

    // If payment notes contain a userId, it must match the saved order.
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

    return res.status(200).json({
      received: true,
      success: true,
    });
  } catch (error) {
    console.error("Webhook error:", error);

    return res.status(500).send("Webhook processing failed");
  }
});

// ============================================
// 13. SUBSCRIPTION STATUS API
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
        expiryDate: subscription.expiryDate,
      });
    } catch (error) {
      console.error("Subscription status error:", error);

      return res.status(500).json({
        success: false,
        message: "Unable to fetch subscription status.",
      });
    }
  }
);

// ============================================
// 14. PROTECTED AI ENDPOINT PLACEHOLDER
// ============================================

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

// ============================================
// 15. HEALTH CHECK
// ============================================

app.get("/", (req, res) => {
  return res.status(200).json({
    success: true,
    service: "Toolgram Main Backend",
    status: "running",
  });
});

app.get("/healthz", (req, res) => {
  return res.status(200).json({
    success: true,
    service: "Toolgram Main Backend",
    status: "running",
  });
});

// ============================================
// 16. ERROR HANDLER
// ============================================

app.use((error, req, res, next) => {
  console.error("Server error:", error.message);

  if (res.headersSent) {
    return next(error);
  }

  if (error.message === "Origin not allowed by CORS") {
    return res.status(403).json({
      success: false,
      message: "This website origin is not allowed.",
    });
  }

  return res.status(500).json({
    success: false,
    message: "Internal server error.",
  });
});

// ============================================
// 17. START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`Toolgram backend running on port ${PORT}`);
  console.log("Allowed website origins:", allowedOrigins);
});








              


        
