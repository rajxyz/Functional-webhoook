const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const Razorpay = require('razorpay');
const app = express();

app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

// -------------------- Firebase Admin --------------------
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

admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

// -------------------- Razorpay --------------------
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_SECRET
});

// -------------------- Create Order --------------------
app.post('/create-order', async (req, res) => {
  try {
    const { userId, referralCode } = req.body;

    // Base price in rupees
    let amount = 1000; // e.g., ₹1000
    let discount = 0;

    // Check referral code
    if (referralCode) {
      const refSnap = await db.collection('users').where("referralCode", "==", referralCode).get();
      if (!refSnap.empty) {
        discount = amount * 0.10; // 10% discount
        amount -= discount;
      }
    }

    const options = {
      amount: amount * 100, // paise
      currency: "INR",
      receipt: `receipt_${userId}_${Date.now()}`,
      notes: { userId, referralCode: referralCode || "" }
    };

    const order = await razorpay.orders.create(options);
    res.send({ success: true, order, discount });
  } catch (err) {
    console.error(err);
    res.status(500).send({ success: false, error: err.message });
  }
});

// -------------------- Razorpay Webhook --------------------
app.post('/razorpay-webhook', async (req, res) => {
  const signature = req.headers['x-razorpay-signature'];
  const webhookSecret = process.env.RAZORPAY_SECRET;

  const generatedSignature = crypto.createHmac('sha256', webhookSecret)
                                   .update(req.rawBody)
                                   .digest('hex');

  if (signature !== generatedSignature) {
    return res.status(403).send({ success: false, error: 'Invalid signature' });
  }

  const event = req.body.event;
  const payload = req.body.payload;

  try {
    let userId = payload.payment?.entity?.notes?.userId;
    let referralCode = payload.payment?.entity?.notes?.referralCode;

    if (!userId && event.startsWith('subscription.')) {
      userId = payload.subscription?.entity?.notes?.userId;
      referralCode = payload.subscription?.entity?.notes?.referralCode;
    }

    if (userId) {
      // Unlock premium
      const userRef = db.collection('subscriptions').doc(userId);
      await userRef.set({
        premium: true,
        expiry_date: admin.firestore.Timestamp.fromDate(new Date(new Date().setFullYear(new Date().getFullYear() + 1)))
      }, { merge: true });

      // Track referral usage
      if (referralCode) {
        const refSnap = await db.collection('users').where("referralCode", "==", referralCode).get();
        if (!refSnap.empty) {
          const refId = refSnap.docs[0].id;
          await db.collection('users').doc(refId).update({
            usedBy: admin.firestore.FieldValue.arrayUnion(userId),
            credits: admin.firestore.FieldValue.increment(10)
          });
        }
      }
    }

    res.status(200).send({ success: true });
  } catch (err) {
    res.status(500).send({ success: false, error: err.message });
  }
});

// -------------------- Health --------------------
app.get('/healthz', (req, res) => res.send({ status: "ok" }));

// -------------------- Start Server --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
