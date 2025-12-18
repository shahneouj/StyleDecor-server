const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { MongoClient, ObjectId } = require('mongodb');
const admin = require('firebase-admin');

dotenv.config();  // Load .env

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: [
      "http://localhost:5173", // Vite
      "http://localhost:3000", // CRA (optional)
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

const port = process.env.PORT || 8000;
app.get('/', (req, res) => {
  res.status(200).send("connect to the server")
})

let db; // global DB reference

async function connectDB() {
  try {
    const client = new MongoClient(process.env.MONGODB_SRC);
    await client.connect();

    db = client.db('StyleDecor_db');

    console.log("✅ Database connected");

    // Initialize Firebase Admin SDK (multiple supported options):
    // 1) FIREBASE_SERVICE_ACCOUNT (JSON string or base64-encoded JSON)
    // 2) FIREBASE_SERVICE_ACCOUNT_PATH (path to JSON file)
    // 3) local file fallback (styledecor...json)
    let firebaseInitialized = false;

    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
      try {
        let raw = process.env.FIREBASE_SERVICE_ACCOUNT;
        let serviceAccount;
        // Try parse as JSON
        try {
          serviceAccount = JSON.parse(raw);
        } catch (e) {
          // Try base64 decode then parse
          try {
            const decoded = Buffer.from(raw, 'base64').toString('utf8');
            serviceAccount = JSON.parse(decoded);
          } catch (err2) {
            throw new Error('FIREBASE_SERVICE_ACCOUNT is set but not valid JSON or base64-encoded JSON');
          }
        }
        admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
        console.log('✅ Firebase Admin initialized from FIREBASE_SERVICE_ACCOUNT');
        firebaseInitialized = true;
      } catch (err) {
        console.warn('⚠️ Failed to initialize Firebase Admin from FIREBASE_SERVICE_ACCOUNT:', err.message);
      }
    }

    if (!firebaseInitialized && process.env.FIREBASE_SERVICE_ACCOUNT_PATH) {
      try {
        const serviceAccount = require(process.env.FIREBASE_SERVICE_ACCOUNT_PATH);
        admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
        console.log('✅ Firebase Admin initialized from FIREBASE_SERVICE_ACCOUNT_PATH');
        firebaseInitialized = true;
      } catch (err) {
        console.warn('⚠️ Failed to initialize Firebase Admin from path:', err.message);
      }
    }

    if (!firebaseInitialized) {
      // Try the project-local file as a last resort (existing behavior)
      try {
        const serviceAccount = require("./styledecor-45ebb-firebase-adminsdk-fbsvc-2cb7ac5bb5.json");
        admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
        console.log('✅ Firebase Admin initialized from local service account file');
        firebaseInitialized = true;
      } catch (err) {
        console.warn('⚠️ Firebase Admin not initialized. Token verification disabled. To enable, set FIREBASE_SERVICE_ACCOUNT (JSON/base64) or FIREBASE_SERVICE_ACCOUNT_PATH.');
      }
    }

    // If INIT_ADMIN_EMAIL set, ensure that user exists and is admin
    const initAdminEmail = process.env.INIT_ADMIN_EMAIL;
    if (initAdminEmail) {
      const usersCollection = db.collection('users');
      await usersCollection.updateOne(
        { email: initAdminEmail },
        { $set: { role: 'admin', updatedAt: new Date() }, $setOnInsert: { createdAt: new Date() } },
        { upsert: true }
      );
      console.log(`✅ Initial admin ensured: ${initAdminEmail}`);
    }

  } catch (error) {
    console.error("❌ DB connection error:", error);
  }
}

connectDB();
// Middleware: verify Firebase ID token (Authorization: Bearer <token>)
async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'No authorization token provided' });
    }
    const idToken = authHeader.split(' ')[1];
    if (!admin.apps.length) {
      return res.status(500).json({ success: false, message: 'Server token verification not configured' });
    }
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = { uid: decoded.uid, email: decoded.email }; // attach
    next();
  } catch (err) {
    console.error('Token verification failed:', err.message);
    res.status(401).json({ success: false, message: 'Invalid auth token' });
  }
}

// Middleware: require the requester to be an admin (based on users collection)
async function requireAdmin(req, res, next) {
  try {
    const email = req.user?.email;
    if (!email) return res.status(401).json({ success: false, message: 'No authenticated user' });
    const usersCollection = db.collection('users');
    const user = await usersCollection.findOne({ email });
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Admin privileges required' });
    }
    next();
  } catch (err) {
    console.error('Admin check failed:', err);
    res.status(500).json({ success: false, message: 'Server error during admin check' });
  }
}
//  API route
app.get('/decoration-services', async (req, res) => {

  try {

    const collection = db.collection('decoration_service');

    const qurey = {}
    const cursor = collection.find(qurey);

    // 4. Execution: Get the results.
    const data = await cursor.toArray();

    // 5. Response: Use standard success codes and JSON for consistency.
    res.status(200).json({
      success: true,
      count: data.length,
      data: data
    });

  } catch (err) {
    // 6. Detailed Error Handling: Log the server-side error for debugging
    //    but send a less-detailed error to the client.
    console.error("Error fetching decoration services:", err);

    res.status(500).json({
      success: false,
      message: "Internal Server Error: Could not retrieve service data."
    });
  }
});


// Get single decoration service by ID
app.get("/decoration-services/:id", async (req, res) => {
  try {
    const { id } = req.params;
    // Validate MongoDB ObjectId
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid service ID",
      });
    }

    const collection = db.collection("decoration_service");

    const service = await collection.findOne({
      _id: new ObjectId(id),
    });

    if (!service) {
      return res.status(404).json({
        success: false,
        message: "Service not found",
      });
    }

    res.status(200).json({
      success: true,
      data: service,
    });
  } catch (err) {
    console.error("Error fetching service details:", err);

    res.status(500).json({
      success: false,
      message: "Internal Server Error: Could not retrieve service",
    });
  }
});
// Create a payment
app.post("/payments", async (req, res) => {
  try {
    const payment = req.body;

    // Basic validation
    if (
      !payment.serviceId ||
      !payment.amount ||
      !payment.customerName ||
      !payment.customerEmail ||
      !payment.paymentMethod
    ) {
      return res.status(400).json({
        success: false,
        message: "Missing required payment fields",
      });
    }

    const paymentsCollection = db.collection("payments");

    const paymentData = {
      serviceId: new ObjectId(payment.serviceId),
      serviceName: payment.serviceName,
      amount: payment.amount,
      customerName: payment.customerName,
      customerEmail: payment.customerEmail,
      phone: payment.phone,
      paymentMethod: payment.paymentMethod,
      status: "paid",
      createdAt: new Date(),
    };

    const result = await paymentsCollection.insertOne(paymentData);

    res.status(201).json({
      success: true,
      message: "Payment successful",
      paymentId: result.insertedId,
    });
  } catch (err) {
    console.error("Payment error:", err);

    res.status(500).json({
      success: false,
      message: "Internal Server Error: Payment failed",
    });
  }
});
// Get all payments
app.get("/payments", async (req, res) => {
  try {
    const payments = await db
      .collection("payments")
      .find()
      .sort({ createdAt: -1 })
      .toArray();

    res.status(200).json({
      success: true,
      count: payments.length,
      data: payments,
    });
  } catch (err) {
    console.error("Fetch payments error:", err);

    res.status(500).json({
      success: false,
      message: "Could not retrieve payments",
    });
  }
});

// Create or update a user (upsert) — intended to be called after registration
app.post('/users', async (req, res) => {
  try {
    const { name, email, role = 'user', photoURL = null } = req.body;

    // Basic validation
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    const usersCollection = db.collection('users');

    const userDoc = {
      name: name || null,
      email,
      role,
      photoURL,
      updatedAt: new Date(),
    };

    const result = await usersCollection.updateOne(
      { email },
      { $set: userDoc, $setOnInsert: { createdAt: new Date() } },
      { upsert: true }
    );

    res.status(200).json({ success: true, result });
  } catch (err) {
    console.error('Error creating/updating user:', err);
    res.status(500).json({ success: false, message: 'Could not create/update user' });
  }
});



// Update user's role (admin-only) or allow server admin secret
app.put('/users/:email/role', verifyToken, async (req, res) => {
  try {
    const targetEmail = req.params.email;
    const { role } = req.body;
    if (!['user', 'decorator', 'admin'].includes(role)) {
      return res.status(400).json({ success: false, message: 'Invalid role' });
    }

    // allow if requester is admin or an ADMIN_SECRET header matches env
    let allowed = false;
    // check admin secret header
    if (req.headers['x-admin-secret'] && process.env.ADMIN_SECRET && req.headers['x-admin-secret'] === process.env.ADMIN_SECRET) {
      allowed = true;
    }

    // otherwise, verify requester's role via DB
    if (!allowed) {
      const usersCollection = db.collection('users');
      const requester = await usersCollection.findOne({ email: req.user.email });
      if (requester && requester.role === 'admin') allowed = true;
    }

    if (!allowed) return res.status(403).json({ success: false, message: 'Admin privileges required' });

    const usersCollection = db.collection('users');
    const result = await usersCollection.updateOne(
      { email: targetEmail },
      { $set: { role, updatedAt: new Date() }, $setOnInsert: { createdAt: new Date() } },
      { upsert: true }
    );

    res.status(200).json({ success: true, result });
  } catch (err) {
    console.error('Error updating user role:', err);
    res.status(500).json({ success: false, message: 'Could not update role' });
  }
});

// Protect GET /users to admin requests only
app.get('/users', verifyToken, requireAdmin, async (req, res) => {
  try {
    const users = await db.collection('users').find().sort({ createdAt: -1 }).toArray();
    res.status(200).json({ success: true, count: users.length, data: users });
  } catch (err) {
    console.error('Error fetching users (admin):', err);
    res.status(500).json({ success: false, message: 'Could not retrieve users' });
  }
});


// Get all users (admin use)
app.get('/users', async (req, res) => {
  try {
    const users = await db.collection('users').find().sort({ createdAt: -1 }).toArray();
    res.status(200).json({ success: true, count: users.length, data: users });
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ success: false, message: 'Could not retrieve users' });
  }
});

// Get single user by email
app.get('/users/:email', async (req, res) => {
  try {
    const { email } = req.params;
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }
    const user = await db.collection('users').findOne({ email });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.status(200).json({ success: true, data: user });
  } catch (err) {
    console.error('Error fetching user by email:', err);
    res.status(500).json({ success: false, message: 'Could not retrieve user' });
  }
});

app.listen(port, () => {
  console.log("🚀 Server running on port", port);
});
