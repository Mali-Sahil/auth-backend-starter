import User from "../models/user.models.js";
import { asyncHandler } from "../utils/async-handler.js";
import { ApiError } from "../utils/api-error.js";
import jwt from "jsonwebtoken";

const verifyJWT = asyncHandler(async function (req, res, next) {
    const token = req.cookies?.accessToken || req.header("Authorization").replace("Bearer ", "");

    if (!token) {
        throw new ApiError(401, "Unauthorized request.");
    }

    try {
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        const user = await User.findById(decodedToken?._id).select(
            "-password -emailVerificationToken -emailVerificationExpiry -refreshToken",
        );

        if (!user) {
            throw new ApiError(401, "Invalid Token--");
        }

        req.user = user;

        next();
    } catch (error) {
        throw new ApiError(401, "Invalid Token");
    }
});

export { verifyJWT };
