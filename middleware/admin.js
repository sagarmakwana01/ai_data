const admin = (req, res, next) =>{
    if(req.isAuthenticated() && req.user.user_role == "ADMIN"){
       return next()
    }
   return res.redirect('/login');
 }
 
 module.exports = admin;