const express = require('express');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const auth = require('../middleware/auth');
const protected = require('../middleware/protected');
const { setFlash } = require('../utils/flash');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const router = express.Router();
const userController = require('../controller/userController');

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
      cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
      cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// Ensure the uploads folder exists
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// router.post('/', protected, userController.postLogout);
router.get('/',protected,userController.getUserhome);
router.get('/importfile',protected,userController.importFile);
router.get('/datatable',protected,userController.userDataTable);
router.get('/fetchTable',protected,userController.fetchUserTableData);
router.get('/users',protected,userController.getUserTable);
router.get('/signup',auth, userController.getSignup);
router.post('/signup',auth, userController.postSignup);
router.get('/verify-email/:token', userController.getEmailverify);
router.get('/login',auth, userController.getLogin);
router.post('/login',auth, userController.postLogin);
router.post('/',protected, userController.postLogout);
router.get('/forgotpassword', auth, userController.getPasswordforget);
router.get('/resetpassword/:id/:token', auth, userController.getPasswordReset);
router.post('/forgotpassword', auth, userController.postPasswordforget);
router.post('/resetpassword', auth, userController.postNewPassword);
router.get('/change-password',userController.getChangePass);
router.post("/change",userController.postChangePass)
router.get("/user/details/:id",userController.viewUserOne)
router.post('/user/edit/:id', userController.editUserRecord);
router.delete('/delete/:id', userController.deleteUser);
router.delete('/delete-user/:id', userController.deleteUserSingle);
router.post('/upload-excel', upload.single('excelFile'),userController.postUploadFile)
router.post('/update-block-status',userController.updateBlock)

// router.post('/sitesmonitor-admin/login', adminauth, userController.postAdminlogin);
// router.post('/checkemailexist', userController.postCheckemailexist);
// router.get('/emailverify/:token', userController.getEmailtokenforverify);

//sociel media
// Google authentication routes
router.get('/nameadd', (req, res) => {
    const id = req?.query?.code
    if (!id) {
      return res.redirect('/login')
    }
    const decode = jwt.verify(id, process.env.CRYPTO_SEC_KET);
    if (!decode) {
      return res.redirect('/login')
    }
    res.render('nameedit.ejs', { user: decode })
  })
  router.post('/nameadd', userController.postNamedAdd)
   router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
   router.get('/microsoft', passport.authenticate('microsoft', { scope: ["user.read"] }));

router.get('/auth/google/callback', (req, res, next) => {
  passport.authenticate('google', { failureRedirect: '/login' }, async (err, user, info) => {

 
    if(info){
      setFlash(res, 'error', info?.message || 'connect admin');
    }

    if (err) {
      setFlash(res, 'error', info?.message || 'An error occurred');
      return res.redirect('/login');
    }
    if (!user) {
      setFlash(res, 'error', info?.message || 'User not found');
      return res.redirect('/login');
    }
    if (user.track == 'No') {
      var code = jwt.sign(user, process.env.CRYPTO_SEC_KET);
      return res.redirect(`/nameadd?code=${code}`);
    }
    req.logIn(user, (err) => {
      if (err) {
        setFlash(res, 'error', 'Login failed');
        return res.redirect('/login');
      }
      res.redirect('/'); // Redirect to a secure page upon successful login
    });
  })(req, res, next);
}
);

router.get('/nameadd', (req, res) => {
  const id = req?.query?.code
  if (!id) {
    return res.redirect('/login')
  }
  const decode = jwt.verify(id, process.env.CRYPTO_SEC_KET);
  if (!decode) {
    return res.redirect('/login')
  }
  res.render('nameedit.ejs', { user: decode })
})

// MICROSOFT start
router.get('/auth/microsoft/callback', (req, res, next) => {
  passport.authenticate('microsoft', { failureRedirect: '/login' }, async (err, user, info) => {
    if (err) {
      console.log(err)
      setFlash(res, 'error', info?.message || 'An error occurred');
      return res.redirect('/login');
    }
    if (!user) {
      setFlash(res, 'error', info?.message || 'User not found');
      return res.redirect('/login');
    }
    if (user.track == 'No') {
      var code = jwt.sign(user, process.env.CRYPTO_SEC_KET);
      return res.redirect(`/nameadd?code=${code}`);
    }
    req.logIn(user, (err) => {
      if (err) {
        setFlash(res, 'error', 'Login failed');
        return res.redirect('/login');
      }
      res.redirect('/'); 
    });
  })(req, res, next);
}
);

// microsoft end

// router.post('/nameadd', userpageController.postNamedAdd)
module.exports = router;
