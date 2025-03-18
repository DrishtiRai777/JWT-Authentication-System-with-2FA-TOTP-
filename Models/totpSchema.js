const mongoose = require('mongoose');

const totpSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User'},
    totpSecret: {type: String, required: true}
});

module.exports = mongoose.model('TOTP', totpSchema);