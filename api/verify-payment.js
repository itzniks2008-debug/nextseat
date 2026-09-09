const crypto = require("crypto");
const Razorpay = require("razorpay");

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

module.exports = async (req, res) => {

  // Allow requests from NextSeat
  res.setHeader(
    "Access-Control-Allow-Origin",
    "https://nextseat.co.in"
  );

  res.setHeader(
    "Access-Control-Allow-Methods",
    "POST, OPTIONS"
  );

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type"
  );

  // Browser preflight
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

    // Check required fields
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

    // --------------------------------
    // 1. VERIFY SIGNATURE
    // --------------------------------

    const body =
      razorpay_order_id +
      "|" +
      razorpay_payment_id;

    const expectedSignature =
      crypto
        .createHmac(
          "sha256",
          process.env.RAZORPAY_KEY_SECRET
        )
        .update(body)
        .digest("hex");

    if (
      expectedSignature.length !==
      razorpay_signature.length
    ) {
      return res.status(400).json({
        success: false,
        message: "Payment verification failed"
      });
    }

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

    // --------------------------------
    // 2. FETCH PAYMENT FROM RAZORPAY
    // --------------------------------

    const payment =
      await razorpay.payments.fetch(
        razorpay_payment_id
      );

    // --------------------------------
    // 3. VERIFY ORDER ID
    // --------------------------------

    if (
      payment.order_id !==
      razorpay_order_id
    ) {
      return res.status(400).json({
        success: false,
        message: "Payment order mismatch"
      });
    }

    // --------------------------------
    // 4. VERIFY AMOUNT
    // ₹3,499 = 349900 paise
    // --------------------------------

    if (payment.amount !== 349900) {
      return res.status(400).json({
        success: false,
        message: "Payment amount mismatch"
      });
    }

    // --------------------------------
    // 5. VERIFY PAYMENT STATUS
    // --------------------------------

    if (payment.status !== "captured") {
      return res.status(400).json({
        success: false,
        message:
          "Payment has not been captured yet"
      });
    }

    // --------------------------------
    // 6. EVERYTHING VERIFIED
    // --------------------------------

    return res.status(200).json({
      success: true,
      message: "Payment verified successfully"
    });

  } catch (error) {

    console.error(
      "Payment verification error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Unable to verify payment"
    });
  }
};
