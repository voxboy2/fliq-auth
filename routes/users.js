const express = require('express');
const {check, validationResult} =  require('express-validator');
const config = require('config');
const router = express.Router();
const User = require('../models/User');
const validate = require('../routes/validate');

const mailgun = require('mailgun-js');
const Password = require('../routes/password');

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sgMail = require('@sendgrid/mail');
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
// const DOMAIN = "sandboxc261c2bc517342cab6b95b6e6354f50e.mailgun.org?";
// const mg = mailgun({ apiKey: process.env.MAILGUN_APIKEY, domain : DOMAIN});


router.post('/', [
    check('name', 'PLease include a valid email').not().isEmpty(),
    check(
        'email',
        'Please include a valid email'
    ).isEmail(),

    check(
        'password',
        'Please enter a password with 6 or more characters'
    ).isLength({ min:6 })
],

async(req,res) => {
    const errors = validationResult(req);

    if(!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }


    const { name, email, password } = req.body;

    try {

        let user = await User.findOne({ email:email });

        if(user) {
            return res.status(400).json({ errors: [{msg: 'User already exists' }]});
        }



    user = new User({
        name,
        email,
        password
    });

    const salt = await bcrypt.genSalt(10);

    user.password = await bcrypt.hash(password, salt);

    await user.save();

    // jwt token

    const payload = {
        user: {
            id: user.id
        }
    }

    jwt.sign(
        payload, config.get('jwtSecret'),
        { expiresIn: 360000 }, (err,token) => {
            if(err) throw err;
            res.json({ token })
        });
    } catch(err) {
        console.error(err.message);
        res.status(500).send('Serve error')
    }
})



router.post('/login',
    [
        check('email', 'Please include a valid email').isEmail(),
        check(
            'password',
            'Please is required'
        ).exists()
    ],
    async (req,res) => {
        const errors = validationResult(req);
        // we check if there are no errors
        if (!errors.isEmpty()) {
           return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;


        try{

        let user = await User.findOne({ email});

        if(!user) {
            return res.status(400).json({ errors: [{msg: 'Invalid Credentials'}]});
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if(!isMatch) {
          return res.status(400).json({ errors: [{msg: 'Invalid Credentials'}]});
        }

        // jwt token
        const payload = {
            user: {
                id: user.id
            }
        }

        jwt.sign(
            payload, config.get('jwtSecret'), 
            { expiresIn: 360000 }, (err,token) => { if(err) throw err;
                                                     res.json({ token })
            });
        } catch(err) {
          console.error(err.message);
          res.status(500).send('Serve error')
        }

    }
);


router.post('/forgot-password',  (req, res) => {
    User.findOne({email: req.body.email})
        .then(user => {
            if (!user) return res.status(401).json({message: 'The email address ' + req.body.email + ' is not associated with any account. Double-check your email address and try again.'});

            //Generate and set password reset token
            user.generatePasswordReset();

            // Save the updated user object
            user.save()
                .then(user => {
                    // send email
                    let link = "http://" + req.headers.host + "/users/reset/" + user.resetPasswordToken;
                    const mailOptions = {
                        to: user.email,
                        from: process.env.FROM_EMAIL,
                        subject: "Password change request",
                        text: `Hi ${user.name} \n 
                    Please click on the following link ${link} to reset your password. \n\n 
                    If you did not request this, please ignore this email and your password will remain unchanged.\n`,
                    };

                    sgMail.send(mailOptions, (error, result) => {
                        if (error) return res.status(500).json({message: error.message});

                        res.status(200).json({message: 'A reset email has been sent to ' + user.email + '.'});
                    });
                })
                .catch(err => res.status(500).json({message: err.message}));
        })
        .catch(err => res.status(500).json({message: err.message}));
}

)


router.get('/reset/:token', (req, res) => {
    User.findOne({resetPasswordToken: req.params.token, resetPasswordExpires: {$gt: Date.now()}})
        .then((user) => {
            if (!user) return res.status(401).json({message: 'Password reset token is invalid or has expired.'});

            //Redirect user to form with the email address
            res.render('reset', {user});
        })
        .catch(err => res.status(500).json({message: err.message}));

}
)



router.post('/reset/:token', [
    check('password').not().isEmpty().isLength({min: 6}).withMessage('Must be at least 6 chars long'),
    check('confirmPassword', 'Passwords do not match').custom((value, {req}) => (value === req.body.password)),
], validate, Password.resetPassword);







module.exports = router;