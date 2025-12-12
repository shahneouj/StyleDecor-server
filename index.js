const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { MongoClient } = require('mongodb');

dotenv.config();  // Load .env

const app = express();
app.use(express.json());
app.use(cors());

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

  } catch (error) {
    console.error("❌ DB connection error:", error);
  }
}

connectDB();

// Example API route
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
app.listen(port, () => {
  console.log("🚀 Server running on port", port);
});
