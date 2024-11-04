const express = require('express');
const passport = require('passport');
const flash = require('connect-flash');
const session = require('express-session');
let cookieParser = require('cookie-parser');
const router = require('./routes/index');
require('dotenv').config();
const nodemailer = require('nodemailer');
const app = express()
app.use(express.json({ limit: '30mb' }));
app.use(express.urlencoded({ limit: '30mb', extended: true }));
app.use('/public', express.static('public'));
app.set('view engine', 'ejs');
app.use(flash());
app.use(cookieParser());

app.use(session({
	secret: process.env.SECRETE,
	resave: false,
	saveUninitialized: false,
	cookie: {   httpOnly: true, maxAge: 1000 * 60 * 60 * 24, secure: false }
}));

const passportConfig = require('./config/passport');
passportConfig(passport);
app.use(passport.initialize());
app.use(passport.session());
app.use((req, res, next) => {
	res.set('Cache-Control', 'no-store')
	next()
});

app.use((req, res, next) => {
	res.locals.session = req.session
	res.locals.user = req.user
	next()
});
app.use(router);
app.listen(process.env.PORT, () => {
	console.log(`connected at ${process.env.PORT}`);
});
