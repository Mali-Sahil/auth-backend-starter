import { Router } from "express";
import { loginUser, registerUser } from "../controllers/auth.controllers.js";
import { validate } from "../middlewares/validator.middleware.js";
import { userRegisterValidator } from "../validators/index.js";

const router = Router();

router.route("/register").post(userRegisterValidator(), validate, registerUser);
// Validator -> Middleware -> Controller

router.route("/login").post(loginUser);

export default router;
