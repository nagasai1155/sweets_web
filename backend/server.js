require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const twilio = require('twilio');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const client = new twilio(accountSid, authToken);

// Store OTPs temporarily
const otpStore = new Map();

// Generate and send OTP
app.post('/api/send-otp', async (req, res) => {
    const { mobile } = req.body;
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const ttl = 5 * 60 * 1000; // 5 minutes TTL

    try {
        await client.messages.create({
            body: `Your Sweet Delights verification code is: ${otp}`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: `+91${mobile}`
        });

        otpStore.set(mobile, { otp, expires: Date.now() + ttl });
        res.json({ success: true, message: 'OTP sent successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Failed to send OTP' });
    }
});

// Verify OTP
app.post('/api/verify-otp', (req, res) => {
    const { mobile, otp } = req.body;
    const storedOtp = otpStore.get(mobile);

    if (!storedOtp || storedOtp.otp !== otp) {
        return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

    if (Date.now() > storedOtp.expires) {
        otpStore.delete(mobile);
        return res.status(400).json({ success: false, message: 'OTP expired' });
    }

    otpStore.delete(mobile);
    res.json({ success: true, message: 'OTP verified successfully' });
});

app.post('/api/mobile-signup', (req, res) => {
    const { mobile } = req.body;
    // Add your actual user registration logic here
    console.log(`User with mobile +91${mobile} registered`);
    res.json({ success: true, message: 'Signup successful' });
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));