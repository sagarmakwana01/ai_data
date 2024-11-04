const prisma = require("../prisma/index");
const { getFlash } = require("../utils/flash");
const passport = require('passport');
const jwt = require('jsonwebtoken');
const CryptoJS = require("crypto-js");
const nodemailer = require('nodemailer');
const {changePassNew,findUserbyUniqueId} = require('../prisma/dbquery')
const crypto = require("crypto")

let transporter = nodemailer.createTransport({
    service: 'gmail',
    type: "SMTP",
    auth: {
        user: process.env.EMAIL_SEND,
        pass: process.env.EMAIL_SEND_PASS
    },
    tls: {
        rejectUnauthorized: false
    },
    logger: true,
    debug: true
})

const sendMails = (mailOptions) => {
    transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
}


exports.getLogin = (req, res) => {
    const errorMessage = getFlash(req, res);
    res.render('login', { message: errorMessage });
}
exports.postLogin = (req, res, next) => {
    const { userid, password } = req.body;
    
    if (!userid || !password) {
        res.send('error', 'All Field Is Required');
        return res.redirect('/login');
    }
    passport.authenticate('user-local', (err, user, info) => {
        // console.log(info, user)
        if (err) {
            res.send({ status: info.message });
            return next(err);
        }
        if (!user) {
            res.send({ status: info.message });
            return next(err);
        }
        req.logIn(user, (err) => {
            if (err) {
                res.send({ status: info.message });
                return next(err);
            }
            req.session.userId = user.id;
            return res.send({ status: 'valid login', url: '/' });

        })

    })(req, res, next)
}
exports.getSignup = (_, res) => {
    res.render('signup')
}
exports.postSignup = async (req, res) => {
    try {
        const user = await prisma.User.findUnique({
            where: {
                email: req.body.userid,
            },
        })
        if (!user) {
            let token = jwt.sign(req.body, process.env.JWT, { expiresIn: '15m' });
            if (!!token) {
                let statusMessage = `
                        Hi,<br/>
                        Thanks for registering, please verify your email by <a href="${req.get('origin')}/verify-email/${token}">clicking here</a>.<br/>
                        Sincerely,<br/>
                        <h4 style="color:red;">This link will expire in 15 minutes.<br>Please note that this link is for your use only and should not be shared with anyone else.</h4>`
                let mailOptions = {
                    from: process.env.EMAIL_SEND,
                    to: req.body.userid,
                    subject: `Verification Mail`,
                    html: statusMessage,
                };
                sendMails(mailOptions)
                res.send({ status: 'valid signup' })
            } else {
                res.send({ status: 'something wrong' })
            }
        } else {
            res.send({ status: 'email found' })
        }
    } catch (error) {
        console.log(error)
        res.send({ status: 'something wrong' })
    }
}
exports.getEmailverify = (req, res) => {
    const token = req.params.token
    jwt.verify(token, process.env.JWT, async function (err, decoded) {
        if (err) {
            res.render('verified_mail', { status: 'not verified' });
        } else {
            try {
                const user = await prisma.User.findUnique({
                    where: {
                        email: decoded.userid,
                    },
                })
                if (!user) {
                    const hashPassword = CryptoJS.AES.encrypt(decoded.password, process.env.CRYPTO_SEC_KET).toString();
                    prisma.user.create({
                        data: {
                            email: decoded.userid,
                            name: decoded.name,
                            password: hashPassword,
                            user_verify: 'Yes'
                        },
                    }).then(async () => {
                        res.render('verified_mail', { status: 'verified' });
                    }).catch(() => {
                        res.render('verified_mail', { status: 'not verified' });
                    })
                } else {
                    res.render('verified_mail', { status: 'already verified' });
                }
            } catch (error) {
                console.log(error)
            }
        }
    });
}
exports.getUserhome = (_, res) => {
    res.render('home')
}
exports.postLogout = (req, res, next) => {
    req.logout((err) => {
        if (err) { return next(err); }
        return res.redirect('/login');
    });
}
exports.postNamedAdd = async (req, res) => {
    try {
        const useQuery = req?.body?.code
        const userName = req?.body?.username

        if (!useQuery) {
            return res.status(500).json({ error: 'Somthings went wrong', data: false, message: false })
        }
        if (!userName) {
            return res.status(400).json({ error: 'The username is required', data: false, message: false })
        }
        const decode = jwt.verify(useQuery, process.env.CRYPTO_SEC_KET);
        if (!decode?.id) {
            return res.redirect('/login')
        }

        await prisma.user.update({
            where: {
                id: parseInt(decode?.id)
            },
            data: {
                name: userName,
                track: 'Yes'
            }
        })
        let mailOptions = {
            from: process.env.EMAIL_SEND,
            to: decode?.email,
            subject: `Welcome`,
            html: '<h1>Welcome</h1>',
        };
        sendMails(mailOptions)
        req.logIn(decode, (err) => {
            if (err) {
                return res.status(500).json({ error: 'Somthings went wrong', data: false, message: false })
            }
            res.status(200).json({ message: true, error: false, data: false }); // Redirect to a secure page upon successful login
        });
    } catch (error) {
        console.log(error)
        return res.status(500).json({ error: 'Somthings went wrong', data: false, message: false })
    }
}

// forget password

// function makerandomid(length) {
//     var result = '';
//     var characters = 'ABCDEFG###HIJKLMNOP@@QRSTUVWXYZabcd#efghi@jklmnopqrstu@@vwxyz0123456789@#@$&$$^@#$%^&*()|!@#%^#<>@@@@@@#######@@@@@######';
//     var charactersLength = characters.length;
//     for (var i = 0; i < length; i++) {
//         result += characters.charAt(Math.floor(Math.random() *
//             charactersLength));
//     }
//     return 'm' + '@' + '1' + result;
// }

exports.getPasswordforget = (req, res) => {
    res.render('forgotpass')
}
exports.postPasswordforget = async (req, res) => {
    try {
        const { email } = req.body;

        // Validate email format if necessary
        if (!email) {
            return res.status(400).json({ message: 'Email is required.' });
        }

        // Check if the user exists
        const user = await prisma.user.findUnique({
            where: { email },
        });

        if (!user) {
            return res.status(404).json({ message: 'No account with that email found.' });
        }

        // Generate a random token for password reset
        const token = crypto.randomBytes(32).toString('hex');
        // console.log('Generated Token:', token);

        // Set the reset token and expiration (valid for 1 hour)
        await prisma.user.update({
            where: { email },
            data: {
                passwordResetToken: token,
                passwordResetExpires: new Date(Date.now() + 3600000), // 1 hour from now
            },
        });

        // Send the reset email using Sendinblue SMTP
        const mailOptions = {
            from: process.env.EMAIL_SEND,
            to: email,
            subject: 'Password Reset',
            html: `
                <p>You requested a password reset</p>
                <p>Click this <a href="http://localhost:2000/resetpassword/${user.id}/${token}">link</a> to reset your password.</p>
            `,
        };

        await transporter.sendMail(mailOptions);

        // Response indicating the email has been sent
        res.status(200).json({ message: 'Password reset email sent.' });
    } catch (error) {
        console.error('Error in postReset:', error);
        res.status(500).json({ message: 'Something went wrong.' });
    }
};
exports.getPasswordReset = async (req, res, next) => {
    try {
        const { userId, token } = req.params;

        // Ensure userId is parsed to an integer and passed to the query
        const user = await prisma.user.findFirst({
            where: {
                id: userId, // Direct integer comparison
                passwordResetToken: token, 
                passwordResetExpires: {
                    gt: new Date(), // Check if the token is still valid (not expired)
                },
            },
        });

        if (!user) {
            return res.status(400).json({ message: 'Token is invalid or has expired.' });
        }

        // If user is found, render the reset password form
        res.render('resetPass', {
            userId: user.id,   // Pass userId to the form
            resetToken: token  // Pass the reset token to the form
        });
    } catch (error) {
        console.error('Error in getPasswordReset:', error);
        res.status(500).json({ message: 'Something went wrong.' });
    }
};
exports.postNewPassword = async (req, res, next) => {
    const { userId, newPassword, resetToken } = req.body;

    try {
        if (!userId) {
            return res.status(400).json({ message: 'User ID is required.' });
        }

        if (!newPassword) {
            return res.status(400).json({ message: 'New password is required.' });
        }

        const trimmedNewPassword = newPassword.trim();

        const user = await prisma.user.findFirst({
            where: {
                id: parseInt(userId),
                passwordResetToken: resetToken,
                passwordResetExpires: {
                    gt: new Date(),
                },
            },
        });

        if (!user) {
            return res.status(400).json({ message: 'Token is invalid or has expired.' });
        }

        // Encrypt the new password
        const encryptedPassword = CryptoJS.AES.encrypt(trimmedNewPassword, process.env.CRYPTO_SEC_KET).toString();

        // Update user password and clear the reset token and expiration
        await prisma.user.update({
            where: { id: parseInt(userId) },
            data: {
                password: encryptedPassword,
                passwordResetToken: null,
                passwordResetExpires: null,
            },
        });

        // Send a success response
        return res.status(200).json({ message: 'Password changed successfully.' });
    } catch (err) {
        console.error('Error in postNewPassword:', err);
        return res.status(500).json({ message: 'An error occurred.' });
    }
};
const decryptPassword = (encryptedPassword) => {
    const bytes = CryptoJS.AES.decrypt(encryptedPassword, process.env.CRYPTO_SEC_KET);
    return bytes.toString(CryptoJS.enc.Utf8);
  };
  
// /change-password
exports.getChangePass = async (req,res)=>{
    res.render("changePass")
}
exports.postChangePass = async (req, res) => {
    const { old_password, new_password } = req.body;

    try {
        const id = req.user.id;
    
        // Check if old_password and new_password are provided
        if (!old_password?.trim() || !new_password?.trim()) {
            return res.status(400).json({ message: "Old Password and New Password are required." });
        }
    
        console.log(id);
        const user = await findUserbyUniqueId(id);
        const originalPassword = decryptPassword(user?.password);
    
        // Check if the old password matches the original password
        if (originalPassword?.trim() !== old_password?.trim()) {
            return res.status(400).json({ message: "Old password does not match." });
        }
    
        const encyPass = CryptoJS.AES.encrypt(new_password.trim(), process.env.CRYPTO_SEC_KET).toString();
        const updateResult = await changePassNew(id, { password: encyPass });
    
        // Check if the password was updated successfully
        if (updateResult) {
            return res.status(200).json({ message: "Password changed successfully." });
        } else {
            return res.status(500).json({ message: "Something went wrong." });
        }
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: error?.message || "Something went wrong." });
    }
};

