const LocalStratagy = require('passport-local').Strategy
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const MicrosoftStrategy  = require("passport-microsoft").Strategy;

const prisma = require('../prisma/index')
const CryptoJS = require("crypto-js");

function init(passport) {
  passport.use('user-local', new LocalStratagy({ usernameField: 'userid' }, async (userid, password, done) => {
      const user = await prisma.user.findUnique({
          where: {
              email: userid,
          },
      });
     
      if (!user) {
          return done(null, false, { message: "No User" });
          
      }

      if (user.user_verify === 'No') {
          return done(null, false, { message: 'Not Verified Email' });
      }
      
      const isCorrectPassword = CryptoJS.AES.decrypt(user.password, process.env.CRYPTO_SEC_KET).toString(CryptoJS.enc.Utf8) === password?.trim();

      if (isCorrectPassword) {
          return done(null, user, { message: "Logged in Successfully" });
      } else {
          return done(null, false, { message: "Wrong Email or Password" });
      }
  }));


  passport.use('admin-local',new LocalStratagy({ usernameField: 'userid' }, async (userid, password, done) => {
    const user = await prisma.User.findUnique({
      where: {
        email: userid,
      },
    })
    // const user = await User.findOne({ where: { email: email } });
    if (!user) {
      return done(null, false, { message: "No Admin Found" })
    }

    if(user.user_role == 'USER'){
      return done(null, false, { message: "No Admin Found" })
    }

    const isCorrectpassword = CryptoJS.AES.decrypt(user.user_password, process.env.CRYPTO_SEC_KET).toString(CryptoJS.enc.Utf8) === password;

    if(isCorrectpassword){
      return done(null, user, { message: "Logged in Succesfully" })
    }else{
      return done(null, false, { message: "Wrong Email or Password" })
    }

  }))

  passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: 'http://localhost:2000/auth/google/callback',
    passReqToCallback: true
  }, async (req, accessToken, refreshToken, profile, done) => {

    const userfind = await prisma.User.findUnique({
      where: {
        email: profile.emails[0].value,
      },
    })

    if (userfind && profile.provider == userfind.provider) {
      return done(null, userfind);
    }
    if (userfind && profile.provider != userfind.provider) {
      return done(null, false, { message: "This email already exists" })
    }
    // Use profile information to create or update a user in your database
    const user = await prisma.User.create({
      data: {
        email: profile.emails[0].value,
        name: profile.displayName,
        provider: profile.provider
      }
    });
    return done(null, user);
  }));

  passport.use(new MicrosoftStrategy({
      clientID: process.env.MICROSOFT_CLIENT_ID,
      clientSecret: process.env.MICROSOFT_SECRET_ID,
      callbackURL: 'http://localhost:2000/auth/microsoft/callback',
      scope: ['user.read'],
    }, async (req, accessToken, refreshToken, profile, done) => {
  
      // console.log("Profile:", profile); 
      const userfind = await prisma.User.findUnique({
        where: {
          email: profile.emails[0].value,
        },
      });
  
      if (userfind && profile.provider == userfind.provider) {
        return done(null, userfind);
      }
      if (userfind && profile.provider != userfind.provider) {
        return done(null, false, { message: "This email already exists" });
      }
  
      // Create or update user
      const user = await prisma.User.create({
        data: {
          email: profile.emails[0].value,
          name: profile.displayName,
          provider: profile.provider
        }
      });
      return done(null, user);
    }));
  



  // passport.use(new FacebookStrategy({
  //   clientID: process.env.FACEBOOK_APP_ID,
  //   clientSecret: process.env.FACEBOOK_APP_SECRET,
  //   callbackURL: 'https://new.sitesmonitoring.com/auth/facebook/callback',
  //   profileFields: ['id', 'emails', 'name'],
  //   passReqToCallback: true // fields that you want to get from Facebook
  // }, async (req,accessToken, refreshToken, profile, done) => {

  //   const userfind = await prisma.User.findUnique({
  //     where: {
  //       email: profile.emails[0].value,
  //     },
  //   })
  //   if (userfind && profile.provider == userfind.provider) {
  //     return done(null, userfind);
  //   }
  //   if (userfind && profile.provider != userfind.provider) {
  //     return done(null, false, { message: "This email already exists" })
  //   }
  //   // Use profile information to create or update a user in your database
  //   const user = await prisma.User.create({
  //     data: {
  //       email: profile.emails[0].value,
  //       name: profile.name.familyName + ' ' + profile.name.givenName,
  //       provider: profile.provider
  //     }
  //   });
  //   return done(null, user);
  // }));

  passport.serializeUser((user, done) => {
    done(null, user.id);
  })

  passport.deserializeUser((id, done) => {
  prisma.user.findUnique({
      where: {
          id: id,
      },
  }).then((result) => {
      done(null, result);
    }).catch((err) => {
      done(err, null);
    })
  })
}
module.exports = init;