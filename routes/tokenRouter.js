const express = require('express');
const Token = require('../Models/tokenSchema');

const router = express.Router();

router.use(express.json()); 

// Get all the tokens
router.get('/', async (req, res) => {
    try {
        const tokens = await Token.find();
        res.json(tokens);
    } catch (err) {
        res.status(500).json({ message: "Error in getting the tokens" });
    }
});

// Save a token
router.post('/saveToken', async (req, res) => {
    try {
        const { userId, token, expiresAt } = req.body;

        // Check if the user already has a refresh token saved
        const existingUser = await Token.findOne({ userId });
        if (existingUser) 
            return res.status(400).json({ message: "User already has a token" });

        // Create and save the new token
        const newToken = new Token({ userId, token, expiresAt });
        await newToken.save();
        return res.status(201).json({ message: "Token saved successfully!" });
    } 
    catch(error) {
        res.status(500).json({ message: "Error saving the token", error });
    }
});

// Delete a token 
router.delete('/deleteToken', async(req, res) => {
    try {
        const { userId } = req.body;
        await Token.findOneAndDelete({ userId });
        res.status(200).json({ message: "Token deleted successfully!" });
    } catch (error) {
        res.status(500).json({ message: "Error deleting the token", error });
    }
});

module.exports = router;
