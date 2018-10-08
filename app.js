'use strict'
const path = require('path')
const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const compression = require('compression')
const awsServerlessExpressMiddleware = require('aws-serverless-express/middleware')
const app = express()
const router = express.Router()
const nunjucks = require('nunjucks');
const passport = require('passport');
const OAuth2CognitoStrategy = require('passport-oauth2-cognito');
const cookieSession = require('cookie-session');
const cookieParser = require('cookie-parser');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;



const cookieExtractor = () => {
    return function (req) {
        var token = null;
        if (req && req.session)
        {
            token = req.session['jwt'];
        }
        return token;
    };
};

const getPublicKey = () => {
    return function (req) {
        return 'adf';
    };
};


const opts = {}
opts.jwtFromRequest = cookieExtractor();
opts.secretOrKey = getPublicKey();
// https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_q4XNRono4/.well-known/jwks.json
opts.issuer = 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_q4XNRono4';
passport.use(new JwtStrategy(opts, function(jwt_payload, done) {
    User.findOne({id: jwt_payload.sub}, function(err, user) {
        if (err) {
            return done(err, false);
        }
        if (user) {
            return done(null, user);
        } else {
            return done(null, false);
            // or you could create a new account
        }
    });
}));


nunjucks.configure([
    path.resolve(__dirname + ''),
    path.resolve(__dirname + '/views'),
    path.resolve(__dirname + '/views/govuk-frontend'),
    path.resolve(__dirname + '/views/govuk-frontend/components'),
], {
    autoescape: true,
    express: app
});
app.set('view engine', 'njk');


const options = {
    // callbackURL: 'https://auw1xbwwy4.execute-api.eu-west-1.amazonaws.com/prod/auth/cognito/callback',
    callbackURL: 'http://localhost:3000/auth/cognito/callback',
    clientDomain: 'https://api3.galesoftware.net',
    clientID: '5kluu0kr96sj93g78h8fueqhuq',
    // clientSecret: 'shhh-its-a-secret',
    region: 'eu-west-1'
};


function verify(accessToken, refreshToken, profile, done) {
    console.log(`Callback from the call to verify ${accessToken}, ${JSON.stringify(profile)}`);
    done(null, profile);
}

app.use(cookieSession({
    name: 'session2',
    keys: [''],

    maxAge: 24 * 60 * 60 * 1000 // 24 hours
}));

app.use(passport.initialize());
passport.use(new OAuth2CognitoStrategy(options, verify));
passport.serializeUser((user, done) => {
    console.log('user is in serialize' + JSON.stringify(user));
    return done(null, user);
});
passport.deserializeUser((obj, done) => {
    console.log('user is in deserialize' + JSON.stringify(obj));
    done(null, obj)
});


app.use(cookieParser(['']));

if (process.env.NODE_ENV === 'test') {
  // NOTE: aws-serverless-express uses this app for its integration tests
  // and only applies compression to the /sam endpoint during testing.
  router.use('/sam', compression())
} else {
  router.use(compression())
}

router.use(cors())
router.use(bodyParser.json())
router.use(bodyParser.urlencoded({ extended: true }))
router.use(awsServerlessExpressMiddleware.eventContext())

// NOTE: tests can't find the views directory without this
app.set('views', path.join(__dirname, 'views'))

router.use((req, res, next)  => {
    console.log('cookie:', JSON.stringify(req.session));
    console.log('is authenticated:', JSON.stringify(req.isAuthenticated()));
    console.log('Cookies: ', req.cookies);

    // console.log('is user:', JSON.stringify(req.user()));
    next();
})

router.get('/', (req, res) => {
  res.render('index', {
    apiUrl: req.apiGateway ? `https://${req.apiGateway.event.headers.Host}/${req.apiGateway.event.requestContext.stage}` : 'http://localhost:3000'
  })
})

router.get('/login',
    passport.authenticate('oauth2-cognito')
);

router.get('/logout', function(req, res){
    console.log(JSON.stringify(req.session) + ' and the user is ');
    req.logout();
    console.log(JSON.stringify(req.session) + ' and the user is ');
    res.redirect('/');
});


app.get('/auth/cognito/callback',
    passport.authenticate('oauth2-cognito'),
    function(req, res) {
        // Successful authentication, redirect home.
        console.log('successful authentication ' + JSON.stringify(req.session));
        console.log('am i auth:  ' + req.isAuthenticated());
        res.redirect('/');
    });

// (req,res) => res.send(req.user)
// );

router.get('/sam1', function (req, res, next) {
    req.session.views = (req.session.views || 0) + 1
    console.log(JSON.stringify(req.session));
    res.end(req.session.views + ' views!')
})

router.get('/changePassword', (req, res) => {
    res.render('changePassword', {
        apiUrl: req.apiGateway ? `https://${req.apiGateway.event.headers.Host}/${req.apiGateway.event.requestContext.stage}` : 'http://localhost:3000'
    })})

router.get('/profile',
    (req, res) => {

    res.render('profile', {
        apiUrl: req.apiGateway ? `https://${req.apiGateway.event.headers.Host}/${req.apiGateway.event.requestContext.stage}` : 'http://localhost:3000'
    })});


// // The aws-serverless-express library creates a server and listens on a Unix
// // Domain Socket for you, so you can remove the usual call to app.listen.
// // app.listen(3000)

app.use('/', router)

//
// Export your express server so you can import it in the lambda function.
module.exports = app
