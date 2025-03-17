const express = require('express');
const mongoose = require('mongoose');
const connectDB = require('./config/db');
const bcrypt = require('bcrypt');
const User = require('./Models/userSchema');
const Token = require('./Models/tokenSchema');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

require('dotenv').config();
const app = express();
const port = 3000;

// Middleware
app.use(express.json());
app.use(bodyParser.json());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

// Connect to MongoDB
connectDB();

// Set EJS as the view engine
app.set('view-engine', 'ejs');

// Middleware to refresh access tokens
const refreshAccessToken = async (req, res, next) => {
    const accessToken = req.cookies.accessToken;
    
    if(!accessToken) {
        return attemptTokenRefresh(req, res, next);
    }

    jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (!err) {
            req.user = user;
            return next();
        }
        return attemptTokenRefresh(req, res, next);
    });
};

// Attempt to refresh token before forcing logout
const attemptTokenRefresh = async (req, res, next) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.redirect('/login');

    // Check if refresh token exists in DB
    const storedToken = await Token.findOne({ token: refreshToken });
    if (!storedToken) return res.redirect('/login');

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async (err, user) => {
        if (err) return res.redirect('/login');

        const newAccessToken = generateAccessToken({ id: user.id });
        res.cookie("accessToken", newAccessToken, {
            httpOnly: true,
            secure: true,
            sameSite: "Strict",
            maxAge: 15 * 60 * 1000, // 15 minutes
        });

        req.user = user;
        next();
    });
};

// Home Route
app.get('/', refreshAccessToken, (req, res) => {
    res.render('index.ejs', { name: "Drishti" });
});

// Redirect if already logged in
function checkAuthenticated(req, res, next) {
    const accessToken = req.cookies.accessToken;

    if(!accessToken) {
        return next();
    }

    jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if(err) {
            return next();
        }
        return res.redirect('/');
    });
}

// Render Registration & Login Pages
app.get('/login', checkAuthenticated, (req, res) => res.render('login.ejs'));
app.get('/register', checkAuthenticated, (req, res) => res.render('register.ejs'));

// Register Route
app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.render('register.ejs', { error: "User already exists" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();

        res.redirect('/login');
    } catch (error) {
        console.error('Error registering user:', error);
        res.render('register.ejs', { error: "Internal Server Error" });
    }
});

// Login Route
app.post('/login', async (req, res) => {
  try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });

      if(!user){
          return res.render('login.ejs', { error: "Email incorrect" });
      }

      const isPasswordValid = await bcrypt.compare(password, user.password);
      if(!isPasswordValid) {
          return res.render('login.ejs', { error: "Password incorrect" });
      }

      const payload = { id: user._id };
      const accessToken = generateAccessToken(payload);
      const refreshToken = generateRefreshToken(payload);

      // Store refresh token in HTTP-only cookie
      res.cookie("refreshToken", refreshToken, {
          httpOnly: true,
          secure: true,
          sameSite: "Strict",
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      });

      // Save refresh token to DB
      await saveToken(user._id, refreshToken);

      // Store access token securely
      res.cookie("accessToken", accessToken, {
          httpOnly: true,
          secure: true,
          sameSite: "Strict",
          maxAge: 15 * 60 * 1000, // 15 minutes
      });

      res.redirect('/');
  } catch (error) {
      console.error('Error logging in:', error);
      res.render('login.ejs', { error: "Internal Server Error. Try again later." });
  }
});

// Save Refresh Token to Database
async function saveToken(userId, refreshToken) {
    await Token.findOneAndDelete({ userId });
    const newToken = new Token({ userId, token: refreshToken, expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 });
    await newToken.save();
}

// Generate Tokens
function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
}

function generateRefreshToken(user) {
    return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
}

// // Refresh Token Route
// app.post('/token', validateRefreshToken, (req, res) => {
//     const accessToken = generateAccessToken({ id: req.user.id });
//     res.cookie("accessToken", accessToken, {
//         httpOnly: true,
//         secure: true,
//         sameSite: "Strict",
//         maxAge: 15 * 60 * 1000, // 15 minutes
//     });
//     res.json({ accessToken });
// });

// Middleware to Validate Refresh Token
async function validateRefreshToken(req, res, next) {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) return res.redirect('/login');

    // Check if refresh token exists in DB
    const storedToken = await Token.findOne({ token: refreshToken });
    if (!storedToken) return res.redirect('/login');

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.redirect('/login');
        req.user = user;
        next();
    });
}

// Logout Route
app.post('/logout', validateRefreshToken, async (req, res) => {
    try {
        // Clear db and cookies
        await Token.findOneAndDelete({ userId: req.user.id });

        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: true,
            sameSite: "Strict"
        });

        res.clearCookie("accessToken", {
            httpOnly: true,
            secure: true,
            sameSite: "Strict"
        });
        res.redirect('/login');
        
    } catch (err) {
        res.status(500).json({ error: "Internal Server Error" });
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
