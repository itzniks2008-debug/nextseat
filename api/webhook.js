const crypto = require("crypto");

module.exports = async (req, res) => {

  // Razorpay webhooks must use POST
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed"
    });
  }

  try {

    const webhookSecret =
      process.env.RAZORPAY_WEBHOOK_SECRET;

    if (!webhookSecret) {
      console.error("Webhook secret is missing");

      return res.status(500).json({
        success: false
      });
    }

    const signature =
      req.headers["x-razorpay-signature"];

    if (!signature) {
      return res.status(400).json({
        success: false,
        message: "Missing webhook signature"
      });
    }

    // Generate expected signature
    const expectedSignature =
      crypto
        .createHmac("sha256", webhookSecret)
        .update(JSON.stringify(req.body))
        .digest("hex");

    // Verify signature
    if (
      expectedSignature.length !== signature.length ||
      !crypto.timingSafeEqual(
        Buffer.from(expectedSignature),
        Buffer.from(signature)
      )
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid webhook signature"
      });
    }

    const event = req.body.event;

    // Payment successfully captured
    if (event === "payment.captured") {

      const payment =
        req.body.payload.payment.entity;

      console.log(
        "Payment captured:",
        payment.id,
        payment.order_id,
        payment.amount
      );
    }

    // Order successfully paid
    if (event === "order.paid") {

      const order =
        req.body.payload.order.entity;

      console.log(
        "Order paid:",
        order.id,
        order.amount_paid
      );
    }

    // Payment failed
    if (event === "payment.failed") {

      const payment =
        req.body.payload.payment.entity;

      console.log(
        "Payment failed:",
        payment.id
      );
    }

    // Always acknowledge valid webhook
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
