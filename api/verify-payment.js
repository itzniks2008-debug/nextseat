const crypto = require("crypto");

module.exports = async (req, res) => {
  // Allow requests from NextSeat
  res.setHeader("Access-Control-Allow-Origin", "https://nextseat.co.in");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  // Handle browser preflight request
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed"
    });
  }

  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature
    } = req.body || {};

    if (
      !razorpay_order_id ||
      !razorpay_payment_id ||
      !razorpay_signature
    ) {
      return res.status(400).json({
        success: false,
        message: "Missing payment details"
      });
    }

    const body =
      razorpay_order_id + "|" + razorpay_payment_id;

    const expectedSignature = crypto
      .createHmac(
        "sha256",
        process.env.RAZORPAY_KEY_SECRET
      )
      .update(body)
      .digest("hex");

    const isValid =
      crypto.timingSafeEqual(
        Buffer.from(expectedSignature),
        Buffer.from(razorpay_signature)
      );

    if (!isValid) {
      return res.status(400).json({
        success: false,
        message: "Payment verification failed"
      });
    }

    return res.status(200).json({
      success: true,
      message: "Payment verified successfully"
    });

  } catch (error) {
    console.error("Payment verification error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to verify payment"
    });
  }
};  
