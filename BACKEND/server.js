const express = require("express");
const path = require("path");
const cors = require("cors");

const app = express();
const PORT = 3001;

/* Middleware */
app.use(cors());
app.use(express.json());

/* Serve frontend files */
const FRONTEND_PATH = path.join(__dirname, "..");
app.use(express.static(FRONTEND_PATH));

/* Health check API */
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    message: "ForensiScan backend running"
  });
});

/* Dummy analyze endpoint (for testing) */
app.post("/api/analyze", (req, res) => {
  res.json({
    success: true,
    ai_probability: Math.floor(Math.random() * 100),
    message: "Demo analysis result"
  });
});



/* Start server */
app.listen(PORT, () => {
  console.log("\n🔬 ForensiScan Backend");
  console.log(`✅ Server running at http://localhost:${PORT}`);
  console.log(`🩺 Health check: http://localhost:${PORT}/api/health\n`);
});
