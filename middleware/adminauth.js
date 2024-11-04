const adminauth = (req, res, next) =>{
    if(!req.isAuthenticated()){
       return next()
    }
   return res.redirect('/sitesmonitor-admin');
 }
 
 module.exports = adminauth;