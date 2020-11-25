const User = require('../models/User');

const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);


exports.resetPassword =  (req,res) => {
    
   User.findOne({resetPasswordToken: req.params.token, resetPasswordExpires: {$gt: Date.now()}})

    .then((user) => {
        if (!user) return res.status(401).json({message: 'Password reset token is invalid or has expired.'});

        //Set the new password
        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        // Save
        user.save((err) => {
            if (err) return res.status(500).json({message: err.message});

            // send email
            const mailOptions = {
                to: user.email,
                from: process.env.FROM_EMAIL,
                subject: "Your password has been changed",
                text: `Hi ${user.name} \n 
                This is a confirmation that the password for your account ${user.email} has just been changed.\n`
            };

            sgMail.send(mailOptions, (error, result) => {
                if (error) return res.status(500).json({message: error.message});

                res.status(200).json({message: 'Your password has been updated.'});
            });
        });
    });

}
