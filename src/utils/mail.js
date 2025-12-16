import Mailgen from "mailgen";

const emailVerificationMailgenContent = (username, verificationUrl) => {
    return {
        body: {
            name: username,
            intro: "Welcome to our Application! We're xcited to have you on board.",
        },
        action: {
            instructions: "To verify your email please click on the button below:",
            button: {
                color: "#2cd440ff",
                text: "Verify your email",
                link: verificationUrl,
            },
        },
        outro: "Need help or have any questions? Just reply to this Email, We'd love to help.",
    };
};

const forgotPasswordMailgenContent = (username, passwordResetUrl) => {
    return {
        body: {
            name: username,
            intro: "We got a request to reset the password of your account",
        },
        action: {
            instructions: "To reset your password click on the button below:",
            button: {
                color: "#2c78d4ff",
                text: "Reset password",
                link: passwordResetUrl,
            },
        },
        outro: "Need help or have any questions? Just reply to this Email, We'd love to help.",
    };
};

export { emailVerificationMailgenContent, forgotPasswordMailgenContent };
