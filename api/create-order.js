const Razorpay = require("razorpay");

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Method not allowed"
    });
  }

  try {
    const { name, email, mobile } = req.body || {};

    if (!name || !email || !mobile) {
      return res.status(400).json({
        success: false,
        message: "Name, email and mobile are required"
      });
    }

    const order = await razorpay.orders.create({
      amount: 349900,
      currency: "INR",
      receipt: `NS_${Date.now()}`,
      notes: {
        name: name,
        email: email,
        mobile: mobile
      }
    });

    return res.status(200).json({
      success: true,
      order
    });

  } catch (error) {
    console.error("Razorpay order error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to create payment order"
    });
  }
};
