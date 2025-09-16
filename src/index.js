const express = require('express');  
const admin = require('firebase-admin');  
const app = express();  
app.use(express.json());  
  
// -------------------- Debug Environment --------------------  
console.log('=== DEBUGGING ENV VARIABLES ===');  
console.log('FIREBASE_PRIVATE_KEY:', process.env.FIREBASE_PRIVATE_KEY ? 'FOUND' : 'MISSING');  
console.log('FIREBASE_PROJECT_ID:', process.env.FIREBASE_PROJECT_ID || 'MISSING');  
console.log('FIREBASE_PRIVATE_KEY_ID:', process.env.FIREBASE_PRIVATE_KEY_ID || 'MISSING');  
console.log('FIREBASE_CLIENT_EMAIL:', process.env.FIREBASE_CLIENT_EMAIL || 'MISSING');  
console.log('FIREBASE_CLIENT_ID:', process.env.FIREBASE_CLIENT_ID || 'MISSING');  
console.log('FIREBASE_CLIENT_CERT_URL:', process.env.FIREBASE_CLIENT_CERT_URL || 'MISSING');  
console.log('MIGRATE_SECRET:', process.env.MIGRATE_SECRET ? 'FOUND' : 'MISSING');  
console.log('===============================');  
  
// Exit if private key is missing  
if (!process.env.FIREBASE_PRIVATE_KEY) {  
  console.error('🚨 ERROR: FIREBASE_PRIVATE_KEY environment variable is missing!');  
  process.exit(1);  
}  
  
// -------------------- Initialize Firebase Admin --------------------  
const serviceAccount = {  
  type: "service_account",  
  project_id: process.env.FIREBASE_PROJECT_ID || "toolgram-5d44f",  
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID || "fallback_private_key_id",  
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),  
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
  // -------------------- Security: Check secret --------------------  
  const secret = req.headers['x-webhook-secret'];

  console.log('🔐 Received webhook secret:', secret);  // <-- Debugging line added

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
  
// -------------------- Health Check --------------------  
app.get('/healthz', (req, res) => {  
  res.send({ status: "ok" });  
});  
  
// -------------------- Start Server --------------------  
const PORT = process.env.PORT || 3000;  
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));


































































