const mongoose = require('mongoose');
require('dotenv').config();

// Connect to db
const connectDB = async() => {
    try {
        console.log('Connecting to MongoDb at', process.env.MONGO_URI);
        await mongoose.connect(process.env.MONGO_URI);
        console.log('Connected to Database!');
    }
    catch(error) {
        console.log('Fail to connect!', error);
    }
};

module.exports = connectDB;