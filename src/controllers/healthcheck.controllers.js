import { ApiResponse } from "../utils/api-response.js";

function healthCheck(req, res) {
    try {
        res.status(200).json(new ApiResponse(200, { message: "Server is running" }));
    } catch (error) {}
}

export default healthCheck;