
const express = require("express");
const admin = require("firebase-admin");
const crypto = require("crypto");
const Razorpay = require("razorpay");

const app = express();
const PORT = process.env.PORT || 3000;

// -------------------- ENV VALIDATION --------------------

const requiredEnv = [
  "FIREBASE_PROJECT_ID",
  "FIREBASE_PRIVATE_KEY",
  "FIREBASE_CLIENT_EMAIL",
  "RAZORPAY_KEY_ID",
  "RAZORPAY_SECRET",
  "RAZORPAY_WEBHOOK_SECRET"
];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    throw new Error(`Missing environment variable: ${key}`);
  }
}

// -------------------- FIREBASE ADMIN --------------------

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

// -------------------- RAZORPAY --------------------

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_SECRET
});

// -------------------- RAW BODY + JSON --------------------

// Express captures raw body for Razorpay webhook verification.
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = Buffer.from(buf);
  }
}));

// -------------------- HELPERS --------------------

function safeCompare(a, b) {
  if (!a || !b || a.length !== b.length) return false;

  return crypto.timingSafeEqual(
    Buffer.from(a),
    Buffer.from(b)
  );
}

function verifyWebhookSignature(req) {
  const signature = req.headers["x-razorpay-signature"];
  if (!signature || !req.rawBody) return false;

  const expected = crypto
    .createHmac("sha256", process.env.RAZORPAY_WEBHOOK_SECRET)
    .update(req.rawBody)
    .digest("hex");

  return safeCompare(signature, expected);
}

// -------------------- FIREBASE AUTH MIDDLEWARE --------------------

async function authenticateUser(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7)
      : null;

    if (!token) {
      return res.status(401).json({
        success: false,
        error: "Authentication token required"
      });
    }

    const decoded = await admin.auth().verifyIdToken(token);

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      error: "Invalid or expired authentication token"
    });
  }
}

// -------------------- SUBSCRIPTION CHECK --------------------

async function checkSubscription(req, res, next) {
  try {
    const uid = req.user.uid;

    const snap = await db
      .collection("subscriptions")
      .doc(uid)
      .get();

    if (!snap.exists) {
      return res.status(403).json({
        success: false,
        premium: false,
        error: "Subscription required"
      });
    }

    const subscription = snap.data();
    const expiry = subscription.expiry_date;

    const active =
      subscription.premium === true &&
      expiry &&
      typeof expiry.toDate === "function" &&
      expiry.toDate().getTime() > Date.now();

    if (!active) {
      return res.status(403).json({
        success: false,
        premium: false,
        error: "Subscription expired or inactive"
      });
    }

    req.subscription = subscription;
    next();
  } catch (error) {
    console.error("Subscription check error:", error);

    return res.status(500).json({
      success: false,
      error: "Unable to verify subscription"
    });
  }
}

// -------------------- CREATE RAZORPAY ORDER --------------------

app.post("/create-order", authenticateUser, async (req, res) => {
  try {
    const uid = req.user.uid;
    const referralCode = String(req.body.referralCode || "").trim();

    // Amount in paise: ₹1000.
    // For ₹19, change this to 1900.
    const baseAmount = 100000;

    let finalAmount = baseAmount;
    let discount = 0;
    let validReferralCode = "";

    if (referralCode) {
      const referralSnap = await db
        .collection("users")
        .where("referralCode", "==", referralCode)
        .limit(1)
        .get();

      if (!referralSnap.empty) {
        const referrerId = referralSnap.docs[0].id;

        // Do not allow self-referral.
        if (referrerId !== uid) {
          discount = Math.floor(baseAmount * 0.10);
          finalAmount = baseAmount - discount;
          validReferralCode = referralCode;
        }
      }
    }

    const order = await razorpay.orders.create({
      amount: finalAmount,
      currency: "INR",
      receipt: `receipt_${uid}_${Date.now()}`,
      notes: {
        userId: uid,
        referralCode: validReferralCode
      }
    });

    // Save pending order to Firestore.
    await db.collection("paymentOrders").doc(order.id).set({
      userId: uid,
      amount: finalAmount,
      currency: "INR",
      status: "created",
      referralCode: validReferralCode,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    return res.json({
      success: true,
      order,
      keyId: process.env.RAZORPAY_KEY_ID,
      discount: discount / 100,
      amount: finalAmount
    });
  } catch (error) {
    console.error("Create order error:", error);

    return res.status(500).json({
      success: false,
      error: "Unable to create payment order"
    });
  }
});

// -------------------- VERIFY PAYMENT (FRONTEND CALLBACK) --------------------

app.post("/verify-payment", authenticateUser, async (req, res) => {
  try {
    const uid = req.user.uid;

    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature
    } = req.body;

    if (
      !razorpay_order_id ||
      !razorpay_payment_id ||
      !razorpay_signature
    ) {
      return res.status(400).json({
        success: false,
        error: "Payment details missing"
      });
    }

    const orderSnap = await db
      .collection("paymentOrders")
      .doc(razorpay_order_id)
      .get();

    if (!orderSnap.exists || orderSnap.data().userId !== uid) {
      return res.status(403).json({
        success: false,
        error: "Invalid payment order"
      });
    }

    const expectedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest("hex");

    if (!safeCompare(razorpay_signature, expectedSignature)) {
      return res.status(403).json({
        success: false,
        error: "Invalid payment signature"
      });
    }

    // Verify actual payment status and order linkage with Razorpay.
    const payment = await razorpay.payments.fetch(razorpay_payment_id);

    if (
      payment.order_id !== razorpay_order_id ||
      payment.status !== "captured" ||
      payment.amount !== orderSnap.data().amount ||
      payment.currency !== "INR"
    ) {
      return res.status(400).json({
        success: false,
        error: "Payment is not captured or does not match the order"
      });
    }

    await activateSubscription(
      uid,
      payment.id,
      orderSnap.data().referralCode
    );

    return res.json({
      success: true,
      premium: true,
      message: "Premium activated successfully"
    });
  } catch (error) {
    console.error("Payment verification error:", error);

    return res.status(500).json({
      success: false,
      error: "Payment verification failed"
    });
  }
});

// -------------------- ACTIVATE SUBSCRIPTION --------------------

async function activateSubscription(uid, paymentId, referralCode) {
  const paymentRef = db.collection("processedPayments").doc(paymentId);

  await db.runTransaction(async (transaction) => {
    const paymentSnap = await transaction.get(paymentRef);

    // Prevent duplicate activation and referral rewards.
    if (paymentSnap.exists) return;

    const subscriptionRef = db.collection("subscriptions").doc(uid);
    const subscriptionSnap = await transaction.get(subscriptionRef);

    const existing = subscriptionSnap.exists
      ? subscriptionSnap.data()
      : {};

    const now = Date.now();
    const existingExpiry =
      existing.expiry_date &&
      typeof existing.expiry_date.toDate === "function"
        ? existing.expiry_date.toDate().getTime()
        : 0;

    // Extend an active subscription; otherwise start from now.
    const startFrom = Math.max(now, existingExpiry);
    const expiry = new Date(startFrom + 30 * 24 * 60 * 60 * 1000);

    transaction.set(subscriptionRef, {
      premium: true,
      expiry_date: admin.firestore.Timestamp.fromDate(expiry),
      plan: "monthly",
      lastPaymentId: paymentId,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    transaction.create(paymentRef, {
      userId: uid,
      paymentId,
      processedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    if (referralCode) {
      const refSnap = await transaction.get(
        db.collection("users")
          .where("referralCode", "==", referralCode)
          .limit(1)
      );

      if (!refSnap.empty && refSnap.docs[0].id !== uid) {
        transaction.set(
          refSnap.docs[0].ref,
          {
            credits: admin.firestore.FieldValue.increment(10)
          },
          { merge: true }
        );
      }
    }
  });
}

// -------------------- RAZORPAY WEBHOOK --------------------

app.post("/razorpay-webhook", async (req, res) => {
  try {
    if (!verifyWebhookSignature(req)) {
      return res.status(403).json({
        success: false,
        error: "Invalid webhook signature"
      });
    }

    if (req.body.event !== "payment.captured") {
      return res.json({ success: true, ignored: true });
    }

    const payment = req.body.payload?.payment?.entity;

    if (!payment || !payment.id || !payment.order_id) {
      return res.status(400).json({
        success: false,
        error: "Invalid payment payload"
      });
    }

    const orderSnap = await db
      .collection("paymentOrders")
      .doc(payment.order_id)
      .get();

    if (!orderSnap.exists) {
      return res.status(400).json({
        success: false,
        error: "Unknown payment order"
      });
    }

    const orderData = orderSnap.data();

    if (
      payment.status !== "captured" ||
      payment.amount !== orderData.amount ||
      payment.currency !== orderData.currency ||
      payment.notes?.userId !== orderData.userId
    ) {
      return res.status(400).json({
        success: false,
        error: "Payment details do not match order"
      });
    }

    await activateSubscription(
      orderData.userId,
      payment.id,
      orderData.referralCode
    );

    await db.collection("paymentOrders")
      .doc(payment.order_id)
      .set({
        status: "paid",
        paymentId: payment.id,
        paidAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });

    return res.json({ success: true });
  } catch (error) {
    console.error("Webhook error:", error);

    return res.status(500).json({
      success: false,
      error: "Webhook processing failed"
    });
  }
});

// -------------------- PROTECTED AI ROUTE --------------------

app.post(
  "/ai-request",
  authenticateUser,
  checkSubscription,
  async (req, res) => {
    try {
      // Add your actual AI logic here.
      return res.json({
        success: true,
        message: "Premium access verified. Add AI logic here."
      });
    } catch (error) {
      console.error("AI route error:", error);

      return res.status(500).json({
        success: false,
        error: "AI request failed"
      });
    }
  }
);

// -------------------- SUBSCRIPTION STATUS --------------------

app.get(
  "/subscription-status",
  authenticateUser,
  async (req, res) => {
    try {
      const snap = await db
        .collection("subscriptions")
        .doc(req.user.uid)
        .get();

      if (!snap.exists) {
        return res.json({
          success: true,
          premium: false,
          status: "free"
        });
      }

      const data = snap.data();
      const expiry = data.expiry_date;

      const active =
        data.premium === true &&
        expiry &&
        typeof expiry.toDate === "function" &&
        expiry.toDate().getTime() > Date.now();

      return res.json({
        success: true,
        premium: Boolean(active),
        status: active ? "premium" : "expired",
        expiry_date: expiry?.toDate?.().toISOString() || null
      });
    } catch (error) {
      console.error("Status error:", error);

      return res.status(500).json({
        success: false,
        error: "Unable to fetch subscription status"
      });
    }
  }
);

// -------------------- HEALTH CHECK --------------------

app.get("/healthz", (req, res) => {
  res.json({ status: "ok" });
});

// -------------------- START SERVER --------------------

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
      
