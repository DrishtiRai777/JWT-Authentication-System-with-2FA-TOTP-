const express = require('express');
const qrcode = require('qrcode');
const speakeasy = require('speakeasy');
const TOTP = require('../Models/totpSchema');
const tempTOTP = require('../Models/tempTotpSchema');
const User = require('../Models/userSchema');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');


//Middleware for authentication
function authenticateUser(req, res, next) {
    const token = req.cookies.auth_token;
    if (!token) return res.redirect('/register');

    try {
        const decoded = jwt.verify(token, process.env.USERID_TOKEN_SECRET);
        req.userId = decoded.id; 
        next();
    } catch (error) {
        res.redirect('/register');
    }
}

//Enable TOTP 
router.get('/', authenticateUser, async (req, res) => {
    try {
        const secret = speakeasy.generateSecret();
        await tempTOTP.create({ userId: req.userId, secret: secret.base32 });

        qrcode.toDataURL(secret.otpauth_url, (err, qrCodeUrl) => {
            if (err) return res.render('enable-totp.ejs', { qrCodeUrl: null, error: "Error generating QR code" });
            res.render('enable-totp.ejs', { qrCodeUrl, error: null });
        });

    } catch (error) {
        res.render('enable-totp.ejs', { qrCodeUrl: null, error: "Internal Server Error" });
    }
});

//Verify TOTP 
router.post('/verify-totp', authenticateUser, async (req, res) => {
    try {
        const { totpCode } = req.body;
        const tempSecretEntry = await tempTOTP.findOne({ userId: req.userId });

        if (!tempSecretEntry) return res.render('enable-totp.ejs', { error: "Session expired. Try again." });

        const isValid = speakeasy.totp.verify({
            secret: tempSecretEntry.secret,  
            encoding: 'base32',
            token: totpCode
        });

        if (!isValid) return res.render('enable-totp.ejs', { error: "Invalid TOTP Code. Try again." });

        await TOTP.create({ userId: req.userId, totpSecret: tempSecretEntry.secret });
        await tempTOTP.deleteOne({ userId: req.userId });

        res.redirect('/login');
    } catch (err) {
        res.status(500).send("Internal Server Error");
    }
});

//Forgot Password 
router.get('/forgetPswd', (req, res) => {
    res.render('forgetPswd.ejs');
});

//Password Reset
router.post('/reset-pswd', async (req, res) => {
    try {
        const { email, totp } = req.body;
        const user = await User.findOne({ email });

        if (!user) return res.render('forgetPswd.ejs', { error: "User doesn't exist" });

        const secretKey = await TOTP.findOne({ userId: user._id });
        if (!secretKey) return res.render('forgetPswd.ejs', { error: "Please turn on 2FA" });

        console.log(secretKey);
        console.log(secretKey.totpSecret);
        console.log(totp);

        const isValid = speakeasy.totp.verify({
            secret: secretKey.totpSecret,  
            encoding: 'base32',
            token: totp,
            window: 2  
        });

        if (!isValid) return res.render('forgetPswd.ejs', { error: "Invalid TOTP Code" });

        //Generate JWT Reset Token
        const resetToken = jwt.sign(
            { userId: user._id }, 
            process.env.JWT_SECRET, 
            { expiresIn: '10m' } 
        );

        res.redirect(`/totp/reset-password?token=${resetToken}`);
        // res.redirect('/reset-password');
    } catch (err) {
        res.status(500).send("Can't Reset Password! Please Try Again.");
    }
});

// Reset Password Page
router.get('/reset-password', async (req, res) => {
    const { token } = req.query;
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        res.render('resetPswd.ejs', { token, error: null });
    } catch (err) {
        res.render('forgetPswd.ejs', { error: "Invalid or expired link" });
    }
});

// Password Update
router.post('/update-password', async (req, res) => {
    const { token, password, confirmPassword } = req.body;

    if (password !== confirmPassword) 
        return res.render('resetPswd.ejs', { error: "Passwords do not match", token });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.findByIdAndUpdate(decoded.userId, { password: hashedPassword });

        res.redirect('/login?message=Password successfully updated');
    } catch (err) {
        res.render('forgetPswd.ejs', { error: "Invalid or expired reset link" });
    }
});

module.exports = router;
