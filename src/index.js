const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const Razorpay = require('razorpay');

const app = express();

/* -------------------- RAW BODY (Webhook) -------------------- */
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

/* -------------------- Firebase Admin -------------------- */
const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

/* -------------------- Razorpay -------------------- */
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_SECRET
});

/* ============================================================
   CREATE ORDER
============================================================ */
app.post('/create-order', async (req, res) => {
  try {
    const { userId, referralCode } = req.body;
    if (!userId) return res.status(400).json({ error: "UserId required" });

    let amount = 1000; // ₹1000
    let discount = 0;

    if (referralCode) {
      const refSnap = await db.collection('users')
        .where("referralCode", "==", referralCode)
        .get();

      if (!refSnap.empty) {
        discount = amount * 0.10;
        amount -= discount;
      }
    }

    const order = await razorpay.orders.create({
      amount: amount * 100,
      currency: "INR",
      receipt: `receipt_${userId}_${Date.now()}`,
      notes: { userId, referralCode: referralCode || "" }
    });

    res.json({ success: true, order, discount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

/* ============================================================
   RAZORPAY WEBHOOK  (AUTO UNLOCK)
============================================================ */
app.post('/razorpay-webhook', async (req, res) => {
  const signature = req.headers['x-razorpay-signature'];
  const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

  const generatedSignature = crypto
    .createHmac('sha256', webhookSecret)
    .update(req.rawBody)
    .digest('hex');

  if (signature !== generatedSignature) {
    return res.status(403).json({ error: "Invalid signature" });
  }

  const event = req.body.event;
  if (event !== "payment.captured") {
    return res.json({ ignored: true });
  }

  try {
    const payment = req.body.payload.payment.entity;
    const userId = payment.notes.userId;
    const referralCode = payment.notes.referralCode;

    if (!userId) return res.json({ ignored: true });

    /* 🔓 AUTO UNLOCK (1 MONTH) */
    const expiry = new Date();
    expiry.setDate(expiry.getDate() + 30);

    await db.collection('subscriptions').doc(userId).set({
      premium: true,
      expiry_date: admin.firestore.Timestamp.fromDate(expiry),
      plan: "monthly",
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    /* Referral reward */
    if (referralCode) {
      const refSnap = await db.collection('users')
        .where("referralCode", "==", referralCode)
        .get();

      if (!refSnap.empty) {
        await db.collection('users').doc(refSnap.docs[0].id).update({
          credits: admin.firestore.FieldValue.increment(10)
        });
      }
    }

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

/* ============================================================
   🔒 AUTO LOCK MIDDLEWARE (REAL-TIME)
============================================================ */
async function checkSubscription(req, res, next) {
  const { userId } = req.body;
  if (!userId) return res.status(401).json({ error: "UserId required" });

  const snap = await db.collection('subscriptions').doc(userId).get();
  if (!snap.exists) {
    return res.status(403).json({ error: "Subscription required" });
  }

  const { premium, expiry_date } = snap.data();
  if (!premium || !expiry_date || expiry_date.toDate() < new Date()) {
    return res.status(403).json({ error: "Subscription expired" });
  }

  next(); // 🔓 Access allowed
}

/* ============================================================
   PROTECTED AI ROUTE (AUTO LOCK WORKS HERE)
============================================================ */
app.post('/ai-request', checkSubscription, async (req, res) => {
  // AI logic yahan aayega
  res.json({ success: true, message: "AI response here" });
});

/* -------------------- Health -------------------- */
app.get('/healthz', (req, res) => res.json({ status: "ok" }));

/* -------------------- Start Server -------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on ${PORT}`));        
