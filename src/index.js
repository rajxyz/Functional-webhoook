const express = require('express');
const admin = require('firebase-admin');
const app = express();
app.use(express.json());

// Read all Firebase credentials from environment variables
const serviceAccount = {
  "type": process.env.FIREBASE_TYPE,
  "project_id": process.env.FIREBASE_PROJECT_ID,
  "private_key_id": process.env.FIREBASE_PRIVATE_KEY_ID,
  "private_key": process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'), // Important!
  "client_email": process.env.FIREBASE_CLIENT_EMAIL,
  "client_id": process.env.FIREBASE_CLIENT_ID,
  "auth_uri": process.env.FIREBASE_AUTH_URI,
  "token_uri": process.env.FIREBASE_TOKEN_URI,
  "auth_provider_x509_cert_url": process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
  "client_x509_cert_url": process.env.FIREBASE_CLIENT_X509_CERT_URL
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

app.post('/migrate', async (req, res) => {
  try {
    const snapshot = await db.collection('subscriptions').get();
    for (const doc of snapshot.docs) {
      const data = doc.data();
      const expiry = data.expiry_date?.toDate();
      const isValid = expiry && expiry > new Date();
      await db.collection('subscriptions').doc(doc.id).set({ premium: isValid }, { merge: true });
    }
    res.send({ success: true, message: `Migration completed for ${snapshot.size} users ✅` });
  } catch (err) {
    console.error(err);
    res.status(500).send({ success: false, error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));






