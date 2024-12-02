const prisma = require("../prisma/index");
const { getFlash } = require("../utils/flash");
const passport = require('passport');
const jwt = require('jsonwebtoken');
const CryptoJS = require("crypto-js");
const nodemailer = require('nodemailer');
const { changePassNew, findUserbyUniqueId } = require('../prisma/dbquery')
const crypto = require("crypto")
const xlsx = require('xlsx');
const fs = require('fs');
const csv = require('csv-parser');


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
    passport.authenticate('admin-local', (err, user, info) => {
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
        const user = await prisma.user.findUnique({
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
                    const currentDate = new Date();
                    prisma.user.create({
                        data: {
                            email: decoded.userid,
                            name: decoded.name,
                            password: hashPassword,
                            user_verify: 'Yes',
                            createdAt: currentDate,
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
            // Token is invalid or expired - Render an EJS page
            return res.status(400).render('errorPage', { 
                message: 'Token is invalid or has expired.' 
            });
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
exports.getChangePass = async (req, res) => {
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

exports.importFile = (_, res) => {
    res.render('importFile')
}

// exports.postUploadFile = async (req, res) => {
//     const { category } = req.body;
//     const file = req.file;

//     if (!file || !category) {
//         return res.status(400).json({ message: 'Category and file are required' });
//     }

//     let fileData = [];

//     const allowedMimes = [
//         'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // .xlsx
//         'application/vnd.ms-excel', // .xls
//         'text/csv', // .csv
//         'application/vnd.ms-excel.sheet.macroenabled.12', // .xlsm
//         'application/vnd.ms-excel.sheet.binary.macroenabled.12' // .xlsb
//     ];

//     if (!allowedMimes.includes(file.mimetype)) {
//         if (fs.existsSync(file.path)) {
//             fs.unlinkSync(file.path);  // Delete the file if it exists
//         }
//         return res.status(400).json({ message: 'Please upload a valid Excel or CSV file.' });
//     }


//     // Parse CSV or Excel file
//     if (file.mimetype === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' || file.mimetype === 'application/vnd.ms-excel') {
//         const workbook = xlsx.readFile(file.path);
//         const sheetName = workbook.SheetNames[0];
//         const sheet = workbook.Sheets[sheetName];
//         fileData = xlsx.utils.sheet_to_json(sheet);
//     } else if (file.mimetype === 'text/csv') {
//         const csvData = [];
//         fs.createReadStream(file.path)
//             .pipe(csv())
//             .on('data', (row) => csvData.push(row))
//             .on('end', async () => {
//                 const validationErrors = validateData(csvData);
//                 if (validationErrors.length > 0) {
//                     fs.unlinkSync(file.path);
//                     return res.status(400).json({ message: 'Validation errors', errors: validationErrors });
//                 }
//                 try {
//                     const result = await saveDataToDatabase(csvData, category);
//                     if (fs.existsSync(file.path)) {
//                         fs.unlinkSync(file.path);  // Delete file after processing
//                     }
//                     res.status(200).json(result);
//                 } catch (error) {
//                     if (fs.existsSync(file.path)) {
//                         fs.unlinkSync(file.path);  // Delete file if there’s an error during DB save
//                     }
//                     res.status(400).json({ message: error.message });
//                 }
//             });
//         return;
//     }

//     const validationErrors = validateData(fileData);
//     if (validationErrors.length > 0) {
//         if (fs.existsSync(file.path)) {
//             fs.unlinkSync(file.path);  // Delete file if there are validation errors
//         }
//         return res.status(400).json({ message: 'Validation errors', errors: validationErrors });
//     }

//     try {
//         const result =  await saveDataToDatabase(fileData, category);
//         if (fs.existsSync(file.path)) {
//             fs.unlinkSync(file.path);  // Delete file after processing
//         }
//         res.status(200).json(result);
//     } catch (error) {
//         if (fs.existsSync(file.path)) {
//             fs.unlinkSync(file.path);  // Delete file if there’s an error during DB save
//         }
//         res.status(400).json({ message: error.message });
//     }
// };

exports.postUploadFile = async (req, res) => {
    const { category } = req.body;
    const file = req.file;

    if (!file || !category) {
        return res.status(400).json({ message: 'Category and file are required' });
    }

    let fileData = [];

    const allowedMimes = [
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // .xlsx
        'application/vnd.ms-excel', // .xls
        'text/csv' // .csv
    ];

    if (!allowedMimes.includes(file.mimetype)) {
        if (fs.existsSync(file.path)) {
            fs.unlinkSync(file.path); // Delete the file if it exists
        }
        return res.status(400).json({ message: 'Please upload a valid Excel or CSV file.' });
    }

    // Parse file
    if (file.mimetype === 'text/csv') {
        const csvData = [];
        await new Promise((resolve, reject) => {
            fs.createReadStream(file.path)
                .pipe(csv())
                .on('data', (row) => csvData.push(row))
                .on('end', () => {
                    fileData = csvData;
                    resolve();
                })
                .on('error', reject);
        });
    } else {
        const workbook = xlsx.readFile(file.path);
        const sheetName = workbook.SheetNames[0];
        const sheet = workbook.Sheets[sheetName];
        fileData = xlsx.utils.sheet_to_json(sheet);
    }

    const missingFieldsRecords = [];
    const validRecords = fileData.filter((record) => {
        if (!record.firstName || record.firstName.trim() === '' ||
            !record.lastName || record.lastName.trim() === '' ||
            !record.roleTitle || record.roleTitle.trim() === '' ||
            !record.linkedinUrl || record.linkedinUrl.trim() === '') {
            missingFieldsRecords.push(record);
            return false; // Exclude invalid record
        }
        return true; // Include valid record
    });

    try {
        const { skippedRecords, newUsers, updatedUsers } = await saveDataToDatabase(validRecords, category);

        if (fs.existsSync(file.path)) {
            fs.unlinkSync(file.path); // Delete the file after processing
        }

        return res.status(200).json({
            message: 'File processed successfully',
            newUsers,
            updatedUsers,
            skippedRecords,
            missingFieldsRecords // Send missing fields records
        });
    } catch (error) {
        if (fs.existsSync(file.path)) {
            fs.unlinkSync(file.path); // Delete the file if there’s an error during DB save
        }
        return res.status(400).json({ message: error.message });
    }
};

async function saveDataToDatabase(data, category) {
    const skippedRecords = [];
    const newUsers = [];
    const updatedUsers = [];

    for (const record of data) {
       
        let companyEmployeeRange = 1;

        if (record.companyEmployeeRange) {
            const range = String(record.companyEmployeeRange); // Ensure it's a string
            const rangeParts = range.split('-'); // Split the range string
            if (rangeParts.length === 2) {
                const max = parseInt(rangeParts[1].trim(), 10); // Get the max value (after the hyphen)
        
                // Store max value if it's a valid number
                if (!isNaN(max)) {
                    companyEmployeeRange = max; // Keep as an integer
                }
            } else {
                // If it's a single number, parse it
                const singleValue = parseInt(range.trim(), 10);
                if (!isNaN(singleValue)) {
                    companyEmployeeRange = singleValue;
                }
            }
        }
        

        const existingRecord = await prisma.userData.findUnique({
            where: { linkedinUrl: record.linkedinUrl }
        });

      
        if (existingRecord) {
            // Update the existing record
            const updatedUser = await prisma.userData.update({
                where: { linkedinUrl: record.linkedinUrl },
                data: {
                    firstName: record.firstName?.trim() || existingRecord.firstName,
                    lastName: record.lastName?.trim() || existingRecord.lastName,
                    roleTitle: record.roleTitle?.trim() || existingRecord.roleTitle,
                    company: record.company?.trim() || existingRecord.company,
                    email: record.email?.trim() || existingRecord.email,
                    phone: record.phone?.trim() || existingRecord.phone,
                    location: record.location?.trim() || existingRecord.location,
                    industry: record.industry?.trim() || existingRecord.industry,
                    companyEmployeeRange: companyEmployeeRange || existingRecord.companyEmployeeRange, // Use empty string or existing value                    tags: record.tags?.trim() || existingRecord.tags,
                    stages: record.stages?.trim() || existingRecord.stages,
                    namePrefix: record.namePrefix?.trim() || existingRecord.namePrefix,
                    middleName: record.middleName?.trim() || existingRecord.middleName,
                    gender: record.gender?.trim() || existingRecord.gender,
                    roleInHeader: record.roleInHeader?.trim() || existingRecord.roleInHeader,
                    category: category?.trim() || existingRecord.category,
                  
                }
            });
            updatedUsers.push(updatedUser);
        } else {
            // Create new record
            const newUser = await prisma.userData.create({
                data: {
                    firstName: record.firstName?.trim() || '',
                    lastName: record.lastName?.trim() || '',
                    roleTitle: record.roleTitle?.trim() || '',
                    company: record.company?.trim() || '',
                    linkedinUrl: record.linkedinUrl?.trim() || '',
                    email: record.email?.trim() || '',
                    phone: record.phone?.trim() || '',
                    location: record.location?.trim() || '',
                    industry: record.industry?.trim() || '',
                    companyEmployeeRange: companyEmployeeRange || 1,
                    tags: record.tags?.trim() || '',
                    stages: record.stages?.trim() || '',
                    namePrefix: record.namePrefix?.trim() || '',
                    middleName: record.middleName?.trim() || '',
                    gender: record.gender?.trim() || '',
                    roleInHeader: record.roleInHeader?.trim() || '',
                    category: category?.trim(),
                   
                }
            });
            newUsers.push(newUser);
        }
    }

    return { skippedRecords, newUsers, updatedUsers };
}

// Function to validate required fields
function validateData(data) {
    const requiredFields = ['firstName', 'roleTitle', 'lastName', 'linkedinUrl',];


    const errors = new Set();

    data.forEach(record => {
        requiredFields.forEach(field => {
            if (!record[field] || record[field].trim() === '') {
                // Check for firstName to use as an identifier
                const name = record.firstName || "Unknown Name";
                const lastName = record.lastName || "Unknown Name";
                const job = record.roleTitle || "Unknown job";
                const url = record.linkedinUrl || "Unknown url";

                // Create a specific error message with the missing field and identifier
                if (name == "Unknown Name") {
                    if (job == "Unknown job") {
                        errors.add(`${field} is required for ${name} ${lastName} `);
                    } else {
                        errors.add(`${field} is required for ${job}`);
                    }
                } else if (job == "Unknown job") {
                    errors.add(`${field} is required for ${name} ${lastName} `);
                } else if (url == "Unknown url") {
                    errors.add(`${field} is required for ${name} ${lastName} `);
                }
            }
        });
    });

    return Array.from(errors);


}

// async function saveDataToDatabase(data, category) {
//     const skippedRecords = [];
//     const newUsers = [];
//     for (const record of data) {
//         const existingRecord = await prisma.userData.findUnique({
//             where: { linkedinUrl: record.linkedinUrl }
//         });

//         if (existingRecord) {
//             // Skip this record if a duplicate linkedinUrl is found
//             skippedRecords.push(record.linkedinUrl);
//             console.log(`Skipping duplicate record for linkedinUrl: ${record.linkedinUrl}, name: ${record.firstName}`);
//             continue;
//         }
//         const newUser = await prisma.userData.create({
//             data: {
//                 firstName: record.firstName || '',
//                 lastName: record.lastName || '',
//                 roleTitle: record.roleTitle || '',
//                 company: record.company || '',
//                 linkedinUrl: record.linkedinUrl || '',
//                 email: record.email || '',
//                 phone: record.phone || '',
//                 location: record.location || '',
//                 industry: record.industry || '',
//                 companyEmployeeRange: record.companyEmployeeRange || '',
//                 tags: record.tags || '',
//                 stages: record.stages || '',
//                 namePrefix: record.namePrefix || '',
//                 middleName: record.middleName || '',
//                 gender: record.gender || '',
//                 roleInHeader: record.roleInHeader || '',
//                 category: category,
//             }
//         });
//         newUsers.push(newUser); 
//     }
//     return {skippedRecords,newUsers };
// }

exports.userDataTable = async (req, res) => {

    try {
        // Fetch all users from the database
        const users = await prisma.userData.findMany();

        // Render the EJS page with the fetched user data
        res.render('userDataTable', { users });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Internal Server Error');
    }
};

exports.fetchUserTableData = async (req, res) => {
    try {
        // Fetch all users from the database
        const users = await prisma.userData.findMany();

        // Send user data as JSON
        res.json(users);
        
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
};



exports.viewUserOne = async (req, res) => {
    const userId = req.params.id;
    try {
        // Find the user by ID (assuming you're using Prisma or another ORM)
        const user = await prisma.userData.findUnique({
            where: { id: parseInt(userId) },
        });

        // Send the user data as JSON
        if (user) {
            res.json(user);
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
};

exports.editUserRecord = async (req, res) => {
    const {
        userId,
        firstName,
        lastName,
        email,
        phone,
        job,
        company,
        linkedinUrl,
        location,
        industry,
        companyEmployeeRange,
        tags,
        stages,
        namePrefix,
        middleName,
        gender,
        roleInHeader,
        category
    } = req.body;

    // Check if userId is passed and is a number
    if (!userId || isNaN(userId)) {
        return res.status(400).json({ message: 'Invalid user ID' });
    }

    // Extract the maximum value from the range or single number
  // Initialize companyEmployeeRangeInt as null to handle optional field
  let companyEmployeeRangeInt = null;

  // Check if companyEmployeeRange is provided and process it
  if (companyEmployeeRange) {
      if (typeof companyEmployeeRange === 'string' && companyEmployeeRange.includes('-')) {
          const rangeParts = companyEmployeeRange.split('-').map(part => parseInt(part.trim(), 10));
          if (rangeParts.some(isNaN)) {
              return res.status(400).json({ message: 'Invalid company employee range format.' });
          }
          companyEmployeeRangeInt = Math.max(...rangeParts); // Take the maximum value from the range
      } else {
          companyEmployeeRangeInt = parseInt(companyEmployeeRange, 10);
          if (isNaN(companyEmployeeRangeInt)) {
              return res.status(400).json({ message: 'Invalid company employee range. It must be a number or a range.' });
          }
      }
  }

    console.log('Update request received for user ID:', userId);

    try {
        // Update user record
        const updatedUser = await prisma.userData.update({
            where: { id: Number(userId) }, // Ensure userId is an integer
            data: {
                firstName,
                lastName,
                email,
                phone,
                roleTitle: job,
                company,
                linkedinUrl,
                location,
                industry,
                companyEmployeeRange: companyEmployeeRangeInt, // Store the maximum value
                tags,
                stages,
                namePrefix,
                middleName,
                gender,
                roleInHeader,
                category,
            },
        });

        res.json({ message: 'User updated successfully', user: updatedUser });
    } catch (error) {
        console.error('Error during update:', error);
        res.status(500).json({ message: 'Error updating user' });
    }
};

// Controller to delete a userData by ID
exports.deleteUser = async (req, res) => {
    const userId = parseInt(req.params.id); // Convert userId to an integer

    try {
        // Check if the user exists
        const user = await prisma.userData.findUnique({
            where: { id: userId },
        });

        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Delete the user from the database
        await prisma.userData.delete({
            where: { id: userId }, // Pass userId as an integer
        });

        return res.status(200).json({ success: true, message: 'User Row deleted successfully' });
    } catch (error) {
        console.error('Error deleting user row:', error);
        return res.status(500).json({ success: false, message: 'Error deleting userData' });
    }
};

exports.deleteUserSingle = async (req, res) => {
    const userDeleteId = parseInt(req.params.id); // Convert userId to an integer

    try {
        // Check if the user exists
        const users = await prisma.user.findUnique({
            where: { id: userDeleteId },
        });

        if (!users) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        // Delete the user from the database
        await prisma.user.delete({
            where: { id: userDeleteId }, // Pass userId as an integer
        });

        return res.status(200).json({ success: true, message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user single:', error);
        return res.status(500).json({ success: false, message: 'Error deleting user' });
    }
};


exports.updateBlock = async (req, res) => {
    const { id, block } = req.body;
    try {
        await prisma.user.update({
            where: { id: parseInt(id) },
            data: { block }
        });
        res.json({ success: true });
    } catch (error) {
        console.error(error);
        res.json({ success: false });
    }
};

exports.getUserTable = async (req, res) => {
    try {
        // Fetch all users from the database
        const usersAll = await prisma.user.findMany();
        res.render('userTable', { usersAll });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Internal Server Error');
    }
};
