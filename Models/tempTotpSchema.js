const mongoose = require('mongoose');

const tempTotpSchema = new mongoose.Schema({
    userId: {type: mongoose.Schema.Types.ObjectId, ref:'User', required: true},
    secret: {type: String, required: true},
    createdAt: {type: Date, default: Date.now, expires:300}
});

module.exports = mongoose.model('tempTOTP', tempTotpSchema);