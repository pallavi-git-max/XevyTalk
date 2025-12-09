import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const MONGO_URI = process.env.MONGODB_URI;

const userSchema = new mongoose.Schema({
    username: String,
    email: String,
    isAdmin: Boolean,
    createdByAdmin: Boolean,
    mustChangePassword: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);

async function checkUser() {
    try {
        await mongoose.connect(MONGO_URI);
        console.log('Connected to MongoDB');

        // Check the most recently created user
        const user = await User.findOne().sort({ _id: -1 });

        if (user) {
            console.log('Latest User:', {
                username: user.username,
                email: user.email,
                mustChangePassword: user.mustChangePassword
            });
        } else {
            console.log('No users found');
        }

        process.exit(0);
    } catch (e) {
        console.error(e);
        process.exit(1);
    }
}

checkUser();
