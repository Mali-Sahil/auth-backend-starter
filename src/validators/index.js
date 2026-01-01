import { body } from "express-validator";

const userRegisterValidator = function () {
    return [
        body("email")
            .trim()
            .notEmpty()
            .withMessage("Email is required.")
            .isEmail()
            .withMessage("Email is invalid."),

        body("username")
            .trim()
            .notEmpty()
            .withMessage("Username cannot be empty.")
            .isLowercase()
            .withMessage("Username should be lowercase.")
            .isLength({ min: 3 })
            .withMessage("Username should be at least 3 characters long."),

        body("password").trim().notEmpty().withMessage("Password is required."),

        body("fullName").optional().trim(),
    ];
};

const userLoginValidator = function () {
    return [
        body("email")
            .notEmpty()
            .withMessage("Email is required.")
            .isEmail()
            .withMessage("Email invalid."),

        body("password").notEmpty().withMessage("Password is required."),
    ];
};

const userChangeCurrentPasswordValidator = function () {
    return [
        body("oldPassword").notEmpty().withMessage("Old password is required"),

        body("newPassword").notEmpty().withMessage("New password is required"),
    ];
};

const userForgotPasswordValidator = function () {
    return [
        body("email")
            .notEmpty()
            .withMessage("Email is required.")
            .isEmail()
            .withMessage("Email is Invalid."),
    ];
};

const userResetForgotPasswordValidator = function () {
    return [body("newPassword").notEmpty("Password is required.")];
};

export {
    userRegisterValidator,
    userLoginValidator,
    userChangeCurrentPasswordValidator,
    userForgotPasswordValidator,
    userResetForgotPasswordValidator,
};
