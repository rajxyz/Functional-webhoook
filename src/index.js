const express = require('express');
const admin = require('firebase-admin');
const app = express();
app.use(express.json());

const serviceAccount = {
  type: "service_account",
  project_id: "toolgram-5d44f",
  private_key_id: "99a936b6df69bc49c5bbad4a851d89f4c255a7fa",
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),  // Important fix
  client_email: "firebase-adminsdk-fbsvc@toolgram-5d44f.iam.gserviceaccount.com",
  client_id: "116235617703354710008",
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40toolgram-5d44f.iam.gserviceaccount.com",
  universe_domain: "googleapis.com"
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








