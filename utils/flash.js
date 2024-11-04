// Utility function to set flash message
function setFlash(res, type, message) {
    res.cookie('flashMonitor', message)
  }
  
  // Utility function to get flash message
  function getFlash(req, res) {
    const message = req?.cookies?.flashMonitor ? req?.cookies?.flashMonitor : null;
    if (message) {
        res.clearCookie('flashMonitor') // Remove the flash message after retrieving it
    }
    return message;
  }

  module.exports = {setFlash, getFlash}