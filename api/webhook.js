const crypto = require("crypto");

module.exports = async (req, res) => {

  // Vercel must NOT parse the body before we verify Razorpay's signature
  // See config at the bottom of this file.

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed"
    });
  }

  try {

    const webhookSecret =
      process.env.RAZORPAY_WEBHOOK_SECRET;

    const signature =
      req.headers["x-razorpay-signature"];

    if (!webhookSecret) {
      console.error("RAZORPAY_WEBHOOK_SECRET is missing");

      return res.status(500).json({
        success: false,
        message: "Webhook secret missing"
      });
    }

    if (!signature) {
      return res.status(400).json({
        success: false,
        message: "Missing Razorpay signature"
      });
    }

    // --------------------------------
    // 1. READ RAW REQUEST BODY
    // --------------------------------

    const chunks = [];

    for await (const chunk of req) {
      chunks.push(
        Buffer.isBuffer(chunk)
          ? chunk
          : Buffer.from(chunk)
      );
    }

    const rawBody = Buffer.concat(chunks);

    // --------------------------------
    // 2. VERIFY RAZORPAY SIGNATURE
    // --------------------------------

    const expectedSignature =
      crypto
        .createHmac("sha256", webhookSecret)
        .update(rawBody)
        .digest("hex");

    if (
      expectedSignature.length !== signature.length ||
      !crypto.timingSafeEqual(
        Buffer.from(expectedSignature),
        Buffer.from(signature)
      )
    ) {
      console.error("Invalid Razorpay webhook signature");

      return res.status(400).json({
        success: false,
        message: "Invalid webhook signature"
      });
    }

    // --------------------------------
    // 3. ONLY PARSE AFTER SIGNATURE
    //    IS VERIFIED
    // --------------------------------

    const body =
      JSON.parse(rawBody.toString("utf8"));

    const event = body.event;

    // --------------------------------
    // 4. PAYMENT CAPTURED
    // --------------------------------

    if (event === "payment.captured") {

      const payment =
        body.payload.payment.entity;

      console.log(
        "Payment captured:",
        payment.id,
        payment.order_id,
        payment.amount
      );
    }

    // --------------------------------
    // 5. ORDER PAID
    // --------------------------------

    if (event === "order.paid") {

      const order =
        body.payload.order.entity;

      console.log(
        "Order paid:",
        order.id,
        order.amount_paid
      );
    }

    // --------------------------------
    // 6. PAYMENT FAILED
    // --------------------------------

    if (event === "payment.failed") {

      const payment =
        body.payload.payment.entity;

      console.log(
        "Payment failed:",
        payment.id
      );
    }

    // --------------------------------
    // 7. WEBHOOK RECEIVED SUCCESSFULLY
    // --------------------------------

    return res.status(200).json({
      success: true
    });

  } catch (error) {

    console.error(
      "Webhook processing error:",
      error
    );

    return res.status(500).json({
      success: false
    });
  }
};


// IMPORTANT:
// Disable Vercel's automatic JSON body parser.
// Razorpay signature verification needs the original raw body.
module.exports.config = {
  api: {
    bodyParser: false
  }
};
