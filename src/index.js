const express = require('express');
const admin = require('firebase-admin');
const app = express();
app.use(express.json());

const serviceAccount = require('./serviceAccount.json'); // Upload this file to Render

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
