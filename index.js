const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { MongoClient, ObjectId } = require('mongodb');
const admin = require('firebase-admin');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(cors({
  origin: [
    "http://localhost:5173",
    "http://localhost:3000",
    "https://styledecor-45ebb.firebaseapp.com"
    // Add your production domain later if needed
  ],
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// ---------- MongoDB Connection (cached for serverless) ----------
const uri = process.env.MONGODB_SRC;
if (!uri) throw new Error("MONGODB_SRC is missing in environment variables");

let client = new MongoClient(uri);
let clientPromise = client.connect();

let db = null;
let firebaseApp = null;

// Setup function - ensures DB and Firebase are ready
async function setupDependencies() {
  if (!db) {
    const connectedClient = await clientPromise;
    db = connectedClient.db('StyleDecor_db');
    console.log("✅ MongoDB connected");
  }

  if (!firebaseApp && !admin.apps.length) {
    if (!process.env.FB_SERVICE_KEY) {
      throw new Error("FB_SERVICE_KEY environment variable is missing");
    }
    const decoded = Buffer.from(process.env.FB_SERVICE_KEY, "base64").toString("utf8");
    let serviceAccount = JSON.parse(decoded);

    // Fix escaped newlines from Vercel env
    if (serviceAccount.private_key) {
      serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
    }

    firebaseApp = admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });
    console.log("✅ Firebase initialized");
  } else if (!firebaseApp) {
    firebaseApp = admin.app();
  }

  // Initial admin setup
  const initAdminEmail = process.env.INIT_ADMIN_EMAIL;
  if (initAdminEmail && db) {
    const usersCollection = db.collection('users');
    await usersCollection.updateOne(
      { email: initAdminEmail },
      {
        $set: { role: 'admin', updatedAt: new Date() },
        $setOnInsert: { createdAt: new Date() }
      },
      { upsert: true }
    );
  }
}

// Call setup at startup (fire and forget, but we'll await in handler too)
setupDependencies().catch(err => console.error("Startup setup error:", err));

// ---------- Middlewares ----------
async function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'No authorization token provided' });
    }
    const idToken = authHeader.split(' ')[1];
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = { uid: decoded.uid, email: decoded.email };
    next();
  } catch (err) {
    console.error('Token verification failed:', err.message);
    res.status(401).json({ success: false, message: 'Invalid auth token' });
  }
}

async function requireAdmin(req, res, next) {
  try {
    const email = req.user?.email;
    if (!email) return res.status(401).json({ success: false, message: 'No authenticated user' });

    const user = await db.collection('users').findOne({ email });
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Admin privileges required' });
    }
    next();
  } catch (err) {
    console.error('Admin check failed:', err);
    res.status(500).json({ success: false, message: 'Server error during admin check' });
  }
}

// ---------- Routes ----------
app.get('/', (req, res) => {
  res.status(200).send("StyleDecor API is running");
});

// Public routes
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

// -----------------------------
// Services (admin CRUD) — stored in 'decoration_service' collection
// -----------------------------

// Get all services (admin)
app.get('/services', verifyToken, requireAdmin, async (req, res) => {
  try {
    const services = await db.collection('decoration_service').find().sort({ createdAt: -1 }).toArray();
    res.status(200).json({ success: true, count: services.length, data: services });
  } catch (err) {
    console.error('Error fetching services:', err);
    res.status(500).json({ success: false, message: 'Could not retrieve services' });
  }
});

// Create a service (admin)
app.post('/services', verifyToken, requireAdmin, async (req, res) => {
  try {
    const { service_name, cost, unit, category, description } = req.body;
    if (!service_name || cost === undefined || !unit || !category) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    const createdByEmail = req.user?.email || null;
    const doc = {
      name: service_name,
      price: Number(cost),
      short: unit,
      category,
      description: description || '',
      createdByEmail,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await db.collection('decoration_service').insertOne(doc);
    res.status(201).json({ success: true, insertedId: result.insertedId });
  } catch (err) {
    console.error('Error creating service:', err);
    res.status(500).json({ success: false, message: 'Could not create service' });
  }
});

// Patch service (admin)
app.patch('/services/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const update = req.body;
    if (!ObjectId.isValid(id)) return res.status(400).json({ success: false, message: 'Invalid id' });

    const allowed = ['service_name', 'cost', 'unit', 'category', 'description'];
    const setObj = {};
    for (const k of allowed) if (update[k] !== undefined) setObj[k] = k === 'cost' ? Number(update[k]) : update[k];
    if (Object.keys(setObj).length === 0) return res.status(400).json({ success: false, message: 'No valid fields to update' });
    setObj.updatedAt = new Date();

    const result = await db.collection('decoration_service').updateOne({ _id: new ObjectId(id) }, { $set: setObj });
    res.status(200).json({ success: true, result });
  } catch (err) {
    console.error('Error updating service:', err);
    res.status(500).json({ success: false, message: 'Could not update service' });
  }
});

// Delete service (admin)
app.delete('/services/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ success: false, message: 'Invalid id' });
    const result = await db.collection('decoration_service').deleteOne({ _id: new ObjectId(id) });
    res.status(200).json({ success: true, deletedCount: result.deletedCount });
  } catch (err) {
    console.error('Error deleting service:', err);
    res.status(500).json({ success: false, message: 'Could not delete service' });
  }
});
// Create a payment
// Create a payment (updated with Stripe support)
app.post("/payments", verifyToken, async (req, res) => {
  try {
    const payment = req.body;
    console.log('Payment data received:', payment);

    // Better error reporting
    const missing = [];
    if (!payment.serviceId) missing.push("serviceId");
    if (!payment.amount) missing.push("amount");
    if (!payment.customerName) missing.push("customerName");
    if (!payment.customerEmail) missing.push("customerEmail");
    if (!payment.paymentMethod) missing.push("paymentMethod");

    if (missing.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Missing required fields: ${missing.join(", ")}`,
        received: payment
      });
    }

    // Validate ObjectId format
    if (!/^[0-9a-fA-F]{24}$/.test(payment.serviceId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid serviceId format. Must be a valid MongoDB ObjectId.",
      });
    }

    const paymentsCollection = db.collection("payments");

    // Check if this is a Stripe payment with paymentIntentId
    const status = payment.paymentIntentId ? 'paid' : 'unpaid';
    const stripePaymentId = payment.paymentIntentId || null;

    const paymentData = {
      serviceId: new ObjectId(payment.serviceId),
      serviceName: payment.serviceName || "Unnamed Service",
      amount: Number(payment.amount),
      customerName: payment.customerName,
      customerEmail: payment.customerEmail,
      phone: payment.phone || null,
      paymentMethod: payment.paymentMethod,
      stripePaymentId: stripePaymentId,
      progress_status: '',
      bookingDate: payment.bookingDate || null,
      status: status,
      progress: 0,
      createdAt: new Date(),
      paymentDate: status === 'paid' ? new Date() : null,
    };

    const result = await paymentsCollection.insertOne(paymentData);

    // If this was a successful Stripe payment, also update the service to track bookings
    if (status === 'paid') {
      // Optionally increment booking count on the service
      await db.collection('decoration_service').updateOne(
        { _id: new ObjectId(payment.serviceId) },
        { $inc: { bookingCount: 1 } }
      );
    }

    res.status(201).json({
      success: true,
      message: status === 'paid'
        ? "Payment completed successfully"
        : "Payment record created successfully",
      paymentId: result.insertedId,
      data: paymentData,
    });
  } catch (err) {
    console.error("Payment error:", err);
    res.status(500).json({
      success: false,
      message: "Internal Server Error: Payment failed",
      error: err.message,
    });
  }
});
// Get unpaid payments
app.get("/payments/unpaid", verifyToken, async (req, res) => {
  try {
    const userEmail = req.user.email
    const query = {
      status: "unpaid",
      customerEmail: userEmail
    };
    const payments = await db
      .collection("payments")
      .find(query)
      .sort({ createdAt: -1 }) // optional: latest first
      .toArray();

    res.status(200).json({
      success: true,
      message: "Unpaid payments retrieved successfully",
      count: payments.length,
      data: payments,
    });
  } catch (error) {
    console.error("Error fetching unpaid payments:", error);
    res.status(500).json({
      success: false,
      message: "Failed to get unpaid payments",
    });
  }
});
// Create a Payment Intent for Stripe
app.post('/create-payment-intent', verifyToken, async (req, res) => {
  try {
    const { amount, currency = 'usd', metadata = {} } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Valid amount is required'
      });
    }

    // Convert amount to cents
    const amountInCents = Math.round(amount);

    // FIX: Check against Stripe's maximum limit ($999,999.99)
    if (amountInCents > 99999999) {
      return res.status(400).json({
        success: false,
        message: 'Amount exceeds maximum allowable payment ($999,999.99)'
      });
    }

    // Create Payment Intent
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amountInCents,
      currency: currency,
      metadata: metadata,
      automatic_payment_methods: {
        enabled: true,
      },
    });

    res.status(200).json({
      success: true,
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id,
    });
  } catch (err) {
    console.error('Stripe Payment Intent Error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to create payment intent',
      error: err.message // This will now only catch unexpected errors
    });
  }
});

// PATCH route to update payment status from unpaid to paid
app.patch('/payments/:id/status-to-paid', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Validate ObjectId
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid payment ID format'
      });
    }

    const paymentsCollection = db.collection('payments');

    // Find the payment
    const payment = await paymentsCollection.findOne({
      serviceId: new ObjectId(id)
    });

    if (!payment) {
      return res.status(404).json({
        success: false,
        message: 'Payment not found'
      });
    }

    // Check if payment is already paid
    if (payment.status === 'paid') {
      return res.status(400).json({
        success: false,
        message: 'Payment is already marked as paid',
        data: payment
      });
    }

    // Only allow unpaid to paid transition
    if (payment.status !== 'unpaid') {
      return res.status(400).json({
        success: false,
        message: `Cannot update payment from '${payment.status}' to 'paid'. Only 'unpaid' payments can be updated.`
      });
    }

    // Check authorization - allow admin or the customer who made the payment
    const userEmail = req.user.email;
    if (userEmail !== payment.customerEmail) {
      // Check if user is admin
      const usersCollection = db.collection('users');
      const user = await usersCollection.findOne({ email: userEmail });
      if (!user || user.role !== 'admin') {
        return res.status(403).json({
          success: false,
          message: 'Not authorized to update this payment'
        });
      }
    }

    // Update payment status to paid
    const updateData = {
      status: 'paid',
      paymentDate: new Date(),
      updatedAt: new Date()
    };

    // Optional: Add Stripe payment ID if provided in request body
    if (req.body.stripePaymentId) {
      updateData.stripePaymentId = req.body.stripePaymentId;
    }

    // Optional: Add payment method if provided
    if (req.body.paymentMethod) {
      updateData.paymentMethod = req.body.paymentMethod;
    }

    const result = await paymentsCollection.updateOne(
      { serviceId: new ObjectId(id) },
      { $set: updateData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        message: 'Payment not found or already updated'
      });
    }

    // Get updated payment
    const updatedPayment = await paymentsCollection.findOne({
      _id: new ObjectId(id)
    });

    // Optional: Update service booking count
    if (payment.serviceId) {
      await db.collection('decoration_service').updateOne(
        { _id: payment.serviceId },
        { $inc: { bookingCount: 1 } }
      );
    }

    res.status(200).json({
      success: true,
      message: 'Payment status updated to paid successfully',
      data: updatedPayment
    });

  } catch (err) {
    console.error('Error updating payment status:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to update payment status',
      error: err.message
    });
  }
});
//delete the  booking
app.delete("/bookings/:id", verifyToken, async (req, res) => {
  try {
    const bookingId = req.params.id;
    const userEmail = req.user.email;
    console.log(bookingId, userEmail);
    if (!ObjectId.isValid(bookingId)) {
      return res.status(400).json({ success: false, message: "Invalid booking ID" });
    }

    const result = await db.collection("payments").deleteOne({
      serviceId: new ObjectId(bookingId),
      customerEmail: userEmail, // 🔐 ownership check
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Booking not found or unauthorized",
      });
    }

    res.status(200).json({
      success: true,
      message: "Booking cancelled successfully",
    });
  } catch (error) {
    console.error("Cancel booking error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to cancel booking",
    });
  }
});
// Get all payments
app.get("/payments", verifyToken, requireAdmin, async (req, res) => {
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
// payment for the user

app.get("/payments/user", verifyToken, async (req, res) => {
  try {
    const usersCollection = db.collection("users");
    const userFromDb = await usersCollection.findOne({ email: req.user.email });

    if (!userFromDb) {
      return res.status(403).json({ success: false, message: "User not found" });
    }

    const paymentsCollection = db.collection("payments");

    let filter = {};
    if (userFromDb.role !== "admin") {
      // Normal user - only see their own payments
      filter = { customerEmail: req.user.email };
    }
    // If admin, filter is empty → return all payments

    const payments = await paymentsCollection
      .find(filter)
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



app.get('/bookings/pending-assignment', verifyToken, requireAdmin, async (req, res) => {
  try {
    const bookings = await db.collection('payments').find({ status: 'paid', 'assignedDecorator.id': { $exists: false } }).sort({ createdAt: -1 }).toArray();
    res.status(200).json({ success: true, count: bookings.length, data: bookings });
  } catch (err) {
    console.error('Error fetching pending bookings:', err);
    res.status(500).json({ success: false, message: 'Could not retrieve pending bookings' });
  }
});

app.patch('/bookings/:id/assign', verifyToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { decoratorId } = req.body;
    if (!ObjectId.isValid(id)) return res.status(400).json({ success: false, message: 'Invalid booking id' });
    if (!decoratorId || !ObjectId.isValid(decoratorId)) return res.status(400).json({ success: false, message: 'Invalid decorator id' });

    const decoratorsCollection = db.collection('decorators');
    const decorator = await decoratorsCollection.findOne({ _id: new ObjectId(decoratorId) });
    if (!decorator) return res.status(404).json({ success: false, message: 'Decorator not found' });

    const bookingsCollection = db.collection('payments');
    const updates = { assignedDecorator: { id: decorator._id, name: decorator.name, email: decorator.email }, assignedAt: new Date(), progress_status: 'assigned', progress: 0, updatedAt: new Date() };
    const result = await bookingsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updates }
    );

    // Return the updated booking so client can update UI without extra fetch
    const updated = await bookingsCollection.findOne({ _id: new ObjectId(id) });
    res.status(200).json({ success: true, result, updated });
  } catch (err) {
    console.error('Error assigning decorator:', err);
    res.status(500).json({ success: false, message: 'Could not assign decorator' });
  }
});

// Get bookings assigned to the current decorator
app.get('/bookings/assigned', verifyToken, async (req, res) => {
  try {
    const email = req.user?.email;
    if (!email) return res.status(401).json({ success: false, message: 'No authenticated user' });
    const bookings = await db.collection('payments').find({ 'assignedDecorator.email': email }).sort({ createdAt: -1 }).toArray();
    res.status(200).json({ success: true, count: bookings.length, data: bookings });
  } catch (err) {
    console.error('Error fetching assigned bookings:', err);
    res.status(500).json({ success: false, message: 'Could not retrieve assigned bookings' });
  }
});

// Update booking status (assigned decorator or admin can update)
app.patch('/bookings/:id/status', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    let { progress_status } = req.body;
    console.log(req.body);
    if (!ObjectId.isValid(id)) return res.status(400).json({ success: false, message: 'Invalid booking id' });
    if (!progress_status) return res.status(400).json({ success: false, message: 'Missing status' });

    // normalize status and validate (accept hyphen or underscore)
    progress_status = String(progress_status).trim().toLowerCase().replace(/-/g, '_');
    const allowedStatuses = ['assigned', 'in_progress', 'completed', 'cancelled'];
    if (!allowedStatuses.includes(progress_status)) return res.status(400).json({ success: false, message: `Invalid status. Allowed: ${allowedStatuses.join(', ')}` });

    const bookingsCollection = db.collection('payments');
    const booking = await bookingsCollection.findOne({ _id: new ObjectId(id) });
    if (!booking) return res.status(404).json({ success: false, message: 'Booking not found' });

    const requesterEmail = (req.user?.email || '').toLowerCase();
    // Allow if requester is assigned decorator or an admin
    let allowed = false;
    const assignedEmail = (booking.assignedDecorator?.email || '').toLowerCase();
    if (assignedEmail && assignedEmail === requesterEmail) allowed = true;
    else {
      // check admin
      const usersCollection = db.collection('users');
      const user = await usersCollection.findOne({ email: requesterEmail });
      if (user && user.role === 'admin') allowed = true;
    }
    if (!allowed) return res.status(403).json({ success: false, message: 'Not authorized to update this booking' });

    const prevStatus = booking.progress_status;

    const updates = { progress_status, statusUpdatedAt: new Date(), updatedAt: new Date() };

    // Accept explicit progress percent (0-100) if provided
    let progress = undefined;
    if (req.body.progress !== undefined) {
      const pnum = Number(req.body.progress);
      if (!Number.isFinite(pnum) || pnum < 0 || pnum > 100) return res.status(400).json({ success: false, message: 'Invalid progress (must be 0-100)' });
      progress = Math.round(pnum);
      updates.progress = progress;
    } else {
      // set sensible defaults when status changes
      if (progress_status === 'assigned' || progress_status === '') updates.progress = 0;
      else if (progress_status === 'in_progress') updates.progress = booking?.progress ? booking.progress : 50;
      else if (progress_status === 'completed') updates.progress = 100;
    }

    if (progress_status === 'completed') updates.completedAt = new Date();
    if (progress_status === 'in_progress' && !booking.startedAt) updates.startedAt = new Date();

    console.log('Booking status update request:', { id, prevStatus, progress_status, progress: updates.progress, requester: requesterEmail, assigned: assignedEmail });

    const result = await bookingsCollection.findOneAndUpdate(
      { _id: new ObjectId(id) },
      { $set: updates },
      { returnDocument: "after" }
    );

    // Return the updated booking document for confirmation
    const updated = await bookingsCollection.findOne({ _id: new ObjectId(id) });

    if (result.matchedCount === 0) {
      console.warn('Booking status update did not match any documents:', { id });
      return res.status(500).json({ success: false, message: 'Failed to update booking' });
    }

    res.status(200).json({ success: true, result, updated, prevStatus });
  } catch (err) {
    console.error('Error updating booking status:', err);
    res.status(500).json({ success: false, message: 'Could not update booking status' });
  }
});
// revenue
app.get('/analytics/revenue-summary', verifyToken, async (req, res) => {
  try {
    const paymentsCollection = db.collection('payments');

    const result = await paymentsCollection.aggregate([
      {
        // Only count "Paid" bookings (where paymentDate exists)
        $match: { paymentDate: { $exists: true, $ne: null } }
      },
      {
        $group: {
          _id: null, // Group everything into one object
          totalRevenue: { $sum: "$amount" },
          totalBookings: { $sum: 1 }
        }
      },
      {
        $project: { _id: 0, totalRevenue: 1, totalBookings: 1 }
      }
    ]).toArray();

    // Handle empty database case
    const data = result[0] || { totalRevenue: 0, totalBookings: 0 };

    res.status(200).json({ success: true, data });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 2. Service Demand - Chart Data
app.get('/analytics/service-demand', verifyToken, async (req, res) => {
  try {
    const paymentsCollection = db.collection('payments');

    const demand = await paymentsCollection.aggregate([
      {
        $match: { paymentDate: { $exists: true, $ne: null } }
      },
      {
        $group: {
          _id: "$serviceName", // Group by the service name
          bookingsCount: { $sum: 1 } // Recharts expects this key
        }
      },
      {
        $project: {
          serviceName: "$_id", // Rename _id to serviceName for the chart
          bookingsCount: 1,
          _id: 0
        }
      },
      { $sort: { bookingsCount: -1 } } // Popular services first
    ]).toArray();

    res.status(200).json({ success: true, data: demand });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});
// Create or update a user (upsert) — intended to be called after registration
app.post('/users', async (req, res) => {
  try {
    const { name, email, role, photoURL = null } = req.body;

    // Basic validation
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }

    const usersCollection = db.collection('users');

    // If user exists, preserve their role; otherwise use provided role or default to 'user'
    const existing = await usersCollection.findOne({ email });
    const roleToUse = existing?.role ?? role ?? 'user';

    const userDoc = {
      name: name || existing?.name || null,
      email,
      role: roleToUse,
      photoURL: photoURL || existing?.photoURL || null,
      updatedAt: new Date(),
    };

    const result = await usersCollection.updateOne(
      { email },
      { $set: userDoc, $setOnInsert: { createdAt: new Date() } },
      { upsert: true }
    );

    res.status(200).json({ success: true, result, role: roleToUse });
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

// PATCH equivalent: update only partial fields like 'role' (preferred semantic)
app.patch('/users/:email/role', verifyToken, async (req, res) => {
  try {
    const targetEmail = req.params.email;
    const { role } = req.body;
    if (!['user', 'decorator', 'admin'].includes(role)) {
      return res.status(400).json({ success: false, message: 'Invalid role' });
    }

    let allowed = false;
    if (req.headers['x-admin-secret'] && process.env.ADMIN_SECRET && req.headers['x-admin-secret'] === process.env.ADMIN_SECRET) {
      allowed = true;
    }

    if (!allowed) {
      const usersCollection = db.collection('users');
      const requester = await usersCollection.findOne({ email: req.user.email });
      if (requester && requester.role === 'admin') allowed = true;
    }

    if (!allowed) return res.status(403).json({ success: false, message: 'Admin privileges required' });

    const usersCollection = db.collection('users');
    // Only modify the 'role' field (partial update)
    const result = await usersCollection.updateOne(
      { email: targetEmail },
      { $set: { role, updatedAt: new Date() }, $setOnInsert: { createdAt: new Date() } },
      { upsert: true }
    );

    res.status(200).json({ success: true, result });
  } catch (err) {
    console.error('Error patching user role:', err);
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
// user update

app.patch('/users/:email', verifyToken, async (req, res) => {
  try {
    const targetEmail = req.params.email;
    const requesterEmail = req.user.email;
    const updates = req.body;

    const usersCollection = db.collection('users');

    // -------------------------------
    // Allowed fields (normal users)
    // -------------------------------
    const allowedFields = ['name', 'phone', 'address', 'photoURL'];
    const updateData = {};

    allowedFields.forEach((field) => {
      if (updates[field] !== undefined) {
        updateData[field] = updates[field];
      }
    });

    // -------------------------------
    // Check admin permission for role update
    // -------------------------------
    if (updates.role) {
      let allowed = false;

      // Admin secret (server-to-server)
      if (
        req.headers['x-admin-secret'] &&
        process.env.ADMIN_SECRET &&
        req.headers['x-admin-secret'] === process.env.ADMIN_SECRET
      ) {
        allowed = true;
      }

      // Admin user check
      if (!allowed) {
        const requester = await usersCollection.findOne({ email: requesterEmail });
        if (requester?.role === 'admin') allowed = true;
      }

      if (!allowed) {
        return res.status(403).json({
          success: false,
          message: 'Admin privileges required to update role',
        });
      }

      if (!['user', 'decorator', 'admin'].includes(updates.role)) {
        return res.status(400).json({
          success: false,
          message: 'Invalid role',
        });
      }

      updateData.role = updates.role;
    }

    // -------------------------------
    // Ownership check (user can update only self)
    // -------------------------------
    if (requesterEmail !== targetEmail && !updateData.role) {
      return res.status(403).json({
        success: false,
        message: 'You can only update your own profile',
      });
    }

    // -------------------------------
    // Perform partial update
    // -------------------------------
    const result = await usersCollection.updateOne(
      { email: targetEmail },
      {
        $set: {
          ...updateData,
          email: targetEmail,
          updatedAt: new Date(),
        },
        $setOnInsert: {
          createdAt: new Date(),
        },
      },
      { upsert: true }
    );

    res.status(200).json({
      success: true,
      message: 'User updated successfully',
      result,
    });
  } catch (err) {
    console.error('Error updating user:', err);
    res.status(500).json({
      success: false,
      message: 'Could not update user',
    });
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

// -----------------------------
// Decorators CRUD (admin only)
// Collection: decorators
// -----------------------------

// Get top decorators (public)
app.get('/decorators/top-decorators', async (req, res) => {
  try {
    const collection = db.collection('decorators');
    const decorators = await collection.find({ active: true }).sort({ rating: -1 }).limit(10).toArray();
    res.status(200).json({ success: true, count: decorators.length, data: decorators });
  } catch (err) {
    console.error('Error fetching top decorators:', err);
    res.status(500).json({ success: false, message: 'Could not retrieve top decorators' });
  }
});

// Get all decorators (admin)
app.get('/decorators', verifyToken, requireAdmin, async (req, res) => {
  try {
    const decorators = await db.collection('decorators').find().sort({ createdAt: -1 }).toArray();
    res.status(200).json({ success: true, count: decorators.length, data: decorators });
  } catch (err) {
    console.error('Error fetching decorators:', err);
    res.status(500).json({ success: false, message: 'Could not retrieve decorators' });
  }
});

// Create decorator (admin)
app.post('/decorators', verifyToken, requireAdmin, async (req, res) => {
  try {
    const { name, email, phone, specialties = [], bio = '', profileImage = null, rating = 0, active = true } = req.body;
    if (!name || !email) return res.status(400).json({ success: false, message: 'Name and email are required' });

    const collection = db.collection('decorators');
    const doc = { name, email, phone: phone || null, specialties: Array.isArray(specialties) ? specialties : ('' + specialties).split(',').map(s => s.trim()).filter(Boolean), bio, profileImage, rating: Number(rating) || 0, active: !!active, createdAt: new Date(), updatedAt: new Date() };
    const result = await collection.insertOne(doc);
    res.status(201).json({ success: true, insertedId: result.insertedId });
  } catch (err) {
    console.error('Error creating decorator:', err);
    res.status(500).json({ success: false, message: 'Could not create decorator' });
  }
});

// Patch decorator (admin) - partial update by id
app.patch('/decorators/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const update = req.body;
    if (!ObjectId.isValid(id)) return res.status(400).json({ success: false, message: 'Invalid id' });
    // only allow these fields to be updated
    const allowed = ['name', 'email', 'phone', 'specialties', 'bio', 'profileImage', 'rating', 'active'];
    const setObj = {};
    for (const k of allowed) if (update[k] !== undefined) setObj[k] = k === 'specialties' && typeof update[k] === 'string' ? update[k].split(',').map(s => s.trim()).filter(Boolean) : update[k];
    if (Object.keys(setObj).length === 0) return res.status(400).json({ success: false, message: 'No valid fields to update' });
    setObj.updatedAt = new Date();

    const collection = db.collection('decorators');
    const result = await collection.updateOne({ _id: new ObjectId(id) }, { $set: setObj });
    res.status(200).json({ success: true, result });
  } catch (err) {
    console.error('Error updating decorator:', err);
    res.status(500).json({ success: false, message: 'Could not update decorator' });
  }
});

// Delete decorator (admin)
app.delete('/decorators/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ success: false, message: 'Invalid id' });
    const collection = db.collection('decorators');
    const result = await collection.deleteOne({ _id: new ObjectId(id) });
    res.status(200).json({ success: true, deletedCount: result.deletedCount });
  } catch (err) {
    console.error('Error deleting decorator:', err);
    res.status(500).json({ success: false, message: 'Could not delete decorator' });
  }
});

// ... rest of your user/decorator routes ...

// ---------------------------------------------------------------------
// Vercel Serverless Export - CRITICAL FIX
// ---------------------------------------------------------------------
module.exports = async (req, res) => {
  try {
    // Ensure DB + Firebase are fully ready before processing request
    await clientPromise;
    await setupDependencies();
  } catch (error) {
    console.error("Critical setup failure:", error);
    return res.status(500).json({ success: false, message: "Server initialization failed" });
  }

  // Now safe to handle the request
  app(req, res);
};