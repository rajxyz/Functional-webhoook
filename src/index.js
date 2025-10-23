const express = require('express');
const admin = require('firebase-admin');
const crypto = require('crypto');
const app = express();

// Middleware to store raw body for Razorpay signature verification
app.use(express.json({
verify: (req, res, buf) => {
req.rawBody = buf;
}
}));

// -------------------- Debug Environment --------------------
console.log('=== DEBUGGING ENV VARIABLES ===');
console.log('FIREBASE_PRIVATE_KEY:', process.env.FIREBASE_PRIVATE_KEY ? 'FOUND' : 'MISSING');
console.log('FIREBASE_PROJECT_ID:', process.env.FIREBASE_PROJECT_ID || 'MISSING');
console.log('FIREBASE_PRIVATE_KEY_ID:', process.env.FIREBASE_PRIVATE_KEY_ID || 'MISSING');
console.log('FIREBASE_CLIENT_EMAIL:', process.env.FIREBASE_CLIENT_EMAIL || 'MISSING');
console.log('FIREBASE_CLIENT_ID:', process.env.FIREBASE_CLIENT_ID || 'MISSING');
console.log('FIREBASE_CLIENT_CERT_URL:', process.env.FIREBASE_CLIENT_CERT_URL || 'MISSING');
console.log('MIGRATE_SECRET:', process.env.MIGRATE_SECRET ? 'FOUND' : 'MISSING');
console.log('RAZORPAY_SECRET:', process.env.RAZORPAY_SECRET ? 'FOUND' : 'MISSING');
console.log('DISABLE_SIGNATURE_CHECK:', process.env.DISABLE_SIGNATURE_CHECK === 'true' ? 'ENABLED' : 'DISABLED');
console.log('===============================');

// Exit if Firebase private key is missing
if (!process.env.FIREBASE_PRIVATE_KEY) {
console.error('🚨 ERROR: FIREBASE_PRIVATE_KEY environment variable is missing!');
process.exit(1);
}

// -------------------- Initialize Firebase Admin --------------------
const serviceAccount = {
type: "service_account",
project_id: process.env.FIREBASE_PROJECT_ID || "toolgram-5d44f",
private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID || "fallback_private_key_id",
private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\n/g, '\n'),
client_email: process.env.FIREBASE_CLIENT_EMAIL || "fallback_client_email",
client_id: process.env.FIREBASE_CLIENT_ID || "fallback_client_id",
auth_uri: "https://accounts.google.com/o/oauth2/auth",
token_uri: "https://oauth2.googleapis.com/token",
auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL || "fallback_cert_url",
universe_domain: "googleapis.com"
};

admin.initializeApp({
credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

// -------------------- Migration Webhook --------------------
app.post('/migrate', async (req, res) => {
const secret = req.headers['x-webhook-secret'];
console.log('🔐 Received migration webhook secret:', secret);

if (secret !== process.env.MIGRATE_SECRET) {
return res.status(403).send({ success: false, error: 'Forbidden: Invalid secret' });
}

try {
const snapshot = await db.collection('subscriptions').get();
for (const doc of snapshot.docs) {
const data = doc.data();
const expiry = data.expiry_date?.toDate();
const isValid = expiry && expiry > new Date();
await db.collection('subscriptions').doc(doc.id).set({ premium: isValid }, { merge: true });
}

console.log(`✅ Migration completed for ${snapshot.size} users`);  
res.send({ success: true, message: `Migration completed for ${snapshot.size} users ✅` });

} catch (err) {
console.error('❌ Migration error:', err);
res.status(500).send({ success: false, error: err.message });
}
});

// -------------------- Razorpay Webhook with Referral --------------------
app.post('/razorpay-webhook', async (req, res) => {
const webhookSecret = process.env.RAZORPAY_SECRET;
const signature = req.headers['x-razorpay-signature'];

// Skip signature verification if testing mode is enabled
if (process.env.DISABLE_SIGNATURE_CHECK !== 'true') {
const generatedSignature = crypto.createHmac('sha256', webhookSecret)
.update(req.rawBody)
.digest('hex');

if (signature !== generatedSignature) {  
  console.log('❌ Invalid Razorpay webhook signature');  
  return res.status(403).send({ success: false, error: 'Invalid signature' });  
}

} else {
console.log('⚡️ Signature validation skipped (testing mode)');
}

const event = req.body.event;
const payload = req.body.payload;

try {
let userId;
let referralCode;

// Capture userId and referralCode from Razorpay notes  
if (event === 'payment.captured') {  
  userId = payload.payment?.entity?.notes?.userId;  
  referralCode = payload.payment?.entity?.notes?.referralCode;  
}  

if (event.startsWith('subscription.')) {  
  userId = payload.subscription?.entity?.notes?.userId;  
  referralCode = payload.subscription?.entity?.notes?.referralCode;  
}  

if (userId) {  
  const userRef = db.collection('subscriptions').doc(userId);  

  // Apply referral discount logic (optional: track referral usage)  
  if (referralCode) {  
    const refSnap = await db.collection('referrals').where("referralCode", "==", referralCode).get();  
    if (!refSnap.empty) {  
      const referrerUID = refSnap.docs[0].id;  
      await db.collection('referrals').doc(referrerUID).update({  
        usedBy: admin.firestore.FieldValue.arrayUnion(userId),  
        rewardCount: admin.firestore.FieldValue.increment(1)  
      });  
    }  
  }  

  // Unlock premium subscription  
  await userRef.set({  
    premium: true,  
    expiry_date: admin.firestore.Timestamp.fromDate(new Date(new Date().setFullYear(new Date().getFullYear() + 1)))  
  }, { merge: true });  

  console.log(`✅ Premium unlocked for user: ${userId} via event ${event}${referralCode ? ` with referral ${referralCode}` : ''}`);  
} else {  
  console.log('⚠️ No userId found in webhook payload');  
}  

res.status(200).send({ success: true });

} catch (err) {
console.error('❌ Razorpay webhook error:', err);
res.status(500).send({ success: false, error: err.message });
}
});

// -------------------- Health Check --------------------
app.get('/healthz', (req, res) => {
res.send({ status: "ok" });
});

// -------------------- Start Server --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(🚀 Server running on port ${PORT}));

