const passport = require('passport');
const jwt = require('jsonwebtoken');
const config = require('./config');

module.exports = function(app) {
    app.get('/verifyToken', function(req, res) {
        var token = req.token;
        if (!token) {
            return res.status(401).send({
                message: 'No token provided'
            });
        }

        jwt.verify(token, config.jwtSecret, function(err, decoded) {
            if (err) {
                return res.status(401).send({
                    message: 'Failed to authenticate token'
                });
            }

            // update token exp
            req.decoded = decoded;    
            return res.sendStatus(200);
        });
    });

    app.get('/auth/google',
        passport.authenticate('google', { 
            scope: ['profile', 'email'] 
        })
    );

    app.get('/auth/google/callback',
        passport.authenticate('google', { 
            failureRedirect: config.failureRedirect 
        }),
        function (req, res) {
            var token = req.user;
            res.cookie('token', token, {
                domain: '.authapp.com'
                // httpOnly: true, // accessible only by the webserver
                // secure: true - only on https
            });

            res.redirect(config.successRedirect);
        }
    );
};