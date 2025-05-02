import 'dotenv/config';
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const twilio = require('twilio');
const mongoose = require('mongoose');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Verify Twilio credentials are loaded
if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN || !process.env.TWILIO_PHONE_NUMBER) {
    console.error('Twilio credentials missing from .env file');
    process.exit(1);
}

const client = twilio(
    process.env.TWILIO_ACCOUNT_SID,
    process.env.TWILIO_AUTH_TOKEN
);

const otpStore = new Map();

// Middleware to clean up expired OTPs
const cleanExpiredOtps = () => {
    const now = Date.now();
    for (const [mobile, { expires }] of otpStore.entries()) {
        if (now > expires) {
            otpStore.delete(mobile);
        }
    }
};

// Send OTP endpoint
app.post('/api/send-otp', async (req, res) => {
    cleanExpiredOtps();
    const { mobile } = req.body;
    
    // Validate mobile number (Indian format)
    if (!mobile || mobile.length !== 10 || !/^[6-9]\d{9}$/.test(mobile)) {
        return res.status(400).json({ 
            success: false, 
            message: 'Invalid Indian mobile number. Must be 10 digits starting with 6-9.' 
        });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const ttl = 5 * 60 * 1000; // 5 minutes TTL

    try {
        console.log(`Attempting to send OTP to +91${mobile}`);
        
        const message = await client.messages.create({
            body: `Your Sweet Delights verification code is: ${otp}. Valid for 5 minutes.`,
            from: process.env.TWILIO_PHONE_NUMBER,
            to: `+91${mobile}`
        });

        console.log('Twilio Message SID:', message.sid);
        otpStore.set(mobile, { otp, expires: Date.now() + ttl });
        
        res.json({ 
            success: true, 
            message: 'OTP sent successfully',
            debugInfo: {
                twilioStatus: message.status,
                toNumber: message.to,
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        console.error('Twilio Error:', error);
        
        let errorMessage = 'Failed to send OTP';
        if (error.code === 21211) {
            errorMessage = 'Invalid phone number format';
        } else if (error.code === 21614) {
            errorMessage = 'This phone number is not currently reachable';
        }

        res.status(500).json({ 
            success: false,
            message: errorMessage,
            errorDetails: {
                code: error.code,
                moreInfo: error.moreInfo,
                status: error.status
            }
        });
    }
});

// Verify OTP endpoint
app.post('/api/verify-otp', (req, res) => {
    cleanExpiredOtps();
    const { mobile, otp } = req.body;
    
    if (!mobile || !otp) {
        return res.status(400).json({ 
            success: false, 
            message: 'Mobile number and OTP are required' 
        });
    }

    const storedOtpData = otpStore.get(mobile);
    
    if (!storedOtpData) {
        return res.status(404).json({ 
            success: false, 
            message: 'OTP not found or expired. Please request a new OTP.' 
        });
    }

    if (storedOtpData.otp !== otp) {
        return res.status(401).json({ 
            success: false, 
            message: 'Invalid OTP' 
        });
    }

    // OTP is valid - remove it from storage
    otpStore.delete(mobile);
    
    res.json({ 
        success: true, 
        message: 'OTP verified successfully' 
    });
});

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// Add auth routes
const authRoutes = require('./routes/authRoutes');
app.use('/api/auth', authRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server Error:', err);
    res.status(500).json({ 
        success: false, 
        message: 'Internal server error' 
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});