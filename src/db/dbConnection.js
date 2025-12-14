import mongoose from "mongoose";

async function connectDB() {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log("✅ MonogDB Connected");
    } catch (error) {
        console.error("❌ MongoDB COnnection Error: ", error);
        process.exit(1);
    }
}

export default connectDB;
