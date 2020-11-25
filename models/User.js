const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const config = require('config');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');



const UserSchema = new mongoose.Schema({

     name : {
         type: String,
         required : true
     },

     email : {
        type: String,
        required : true
     },

     password : {
        type: String,
        required : true
     },

     resetPasswordToken: {
      type: String,
      required: false
  },

  resetPasswordExpires: {
      type: Date,
      required: false
  }
}, {timestamps: true});

     
UserSchema.pre('save',  function(next) {
   const user = this;

   if (!user.isModified('password')) return next();

   bcrypt.genSalt(10, function(err, salt) {
       if (err) return next(err);

       bcrypt.hash(user.password, salt, function(err, hash) {
           if (err) return next(err);

           user.password = hash;
           next();
       });
   });
});

UserSchema.methods.comparePassword = function(password) {
   return bcrypt.compareSync(password, this.password);
};




UserSchema.methods.generatePasswordReset = function() {
   this.resetPasswordToken = crypto.randomBytes(20).toString('hex');
   this.resetPasswordExpires = Date.now() + 3600000; //expires in an hour
};


// module.exports = User = mongoose.model('user', UserSchema);


module.exports = User = mongoose.model("User", UserSchema);
