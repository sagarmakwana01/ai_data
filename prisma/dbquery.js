const prisma = require("../prisma/index");

exports.getUserbyemail = (email) => {
    return prisma.user.findUnique({
        where: {
            email: email
        }
    })
}

exports.updateUserpassword = (id,password,email)=>{
    return prisma.user.update({
      where:{
          id: parseInt(id)
      },
      data:{
          email: email,
          password: password
      }
    })
}

exports.findUserbyUniqueId = (id) => {

    if (!id) {
      throw new Error('User ID is required');
    }
  
    return prisma.user.findUnique({
      where: {
        id: parseInt(id), // Ensure ID is an integer if it's stored as such
      },
    });
  }

  exports.changePassNew = (id, password) => {
    return prisma.user.update({
      where:{
        id: parseInt(id)
      },
      data:{
        ...password
      }
    })
  }