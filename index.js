const express = require("express");
const cors = require("cors");
const cloudinary = require("cloudinary").v2;
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

// CONFIG CLOUDINARY
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET,
});

// DELETE IMAGE API
app.post("/delete-image", async (req, res) => {
  try {
    const { public_id } = req.body;

    if (!public_id) {
      return res.status(400).json({ error: "Missing public_id" });
    }

    const result = await cloudinary.uploader.destroy(public_id);

    return res.json({
      success: true,
      result,
    });

  } catch (error) {
    console.log(error);
    return res.status(500).json({ error: error.message });
  }
});

// START SERVER
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});