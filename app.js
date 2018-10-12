'use strict'
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const compression = require('compression');
const awsServerlessExpressMiddleware = require('aws-serverless-express/middleware');
const app = express();
const router = express.Router();
const nunjucks = require('nunjucks');
const passport = require('passport');
// const OAuth2CognitoStrategy = require('passport-oauth2-cognito');
const OAuth2CognitoStrategy = require('./helpers/passport-cognito-oauth2/lib/strategy');
const OpenIDCognitoStrategy = require('./helpers/passport-cognito-openidconnect/lib/strategy');
const cookieSession = require('cookie-session');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwksClient = require('jwks-rsa');
const jwt = require('jsonwebtoken');



// passport.use(new OpenIDCognitoStrategy({
//         domain: 'api3.galesoftware.net',
//         clientID: '1jn4n0sc7i3733mbn5rjfgmk5d',
//         clientSecret: 'ggevn2508u5p7oaf0ep80ct07bc62ej8ksef4nti70khl1annup',
//         callbackURL: 'http://localhost:3000/auth/cognito/callback'
//
//     },
//     function(issuer, audience, profile, cb) {
//         //not interested in passport profile normalization,
//         //just the Auth0's original profile that is inside the _json field
//         return cb(null, profile._json);
//     }));
//






const accessTokenExtractor = function (req, res) {
    if (req.isAuthenticated()) {
        return req.user.accessToken;
    }

    return '';
};

const isAuthenticated = function(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    } else {
        return res.redirect('/login');
    }
};

const isBlah = function(req, res, next) {
        console.log('hello');
        const token = accessTokenExtractor(req, res);
        const decodedToken = jwt.decode(token, {complete: true});
        const jwtPayload = decodedToken.payload;
        const jwtHeader = decodedToken.header;
        const iss = jwtPayload.iss;
        const options ={};
        options.jwksUri = `${iss}/.well-known/jwks.json`;
        console.log(options.jwksUri);
        options.cache = true;
        options.rateLimit = true;
        const client = jwksClient(options);
        const kid = jwtHeader.kid;
        console.log(jwtHeader);
        client.getSigningKey(kid+'234', (err, key) => {
            if (err) { return next(new Error('failed to get the signing key', err)); }

            const signingKey = key.publicKey || key.rsaPublicKey;
            console.log(signingKey);
            // verify token
            var decoded = jwt.verify(token, signingKey);
            console.log(decoded);

            return next();
        });
};

// const getPublicKey = () => {
//     return function (req) {
//         const token = accessTokenExtractor();
//         const decodedToken = jwt.decode(token);
//
//         const iss = decodedToken.iss;
//         const options ={};
//         options.jwksUri = iss;
//         const client = jwksClient(options);
//         const kid = 'RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg';
//         client.getSigningKey(kid, (err, key) => {
//             const signingKey = key.publicKey || key.rsaPublicKey;
//
//             // Now I can use this to configure my Express or Hapi middleware
//         });
//
//         return 'adf';
//     };
// };


// authenticate the web token
// 1. decode the accesss token
// 2. get the issuer and make sure it matches the correct pattern
// 3. if issuer matches then get the .well known address.
// 4: use jwks-rsa to get the signing key (kid found in header of jwt).
// 5: use signing key to validate the jwt.

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

app.use(cookieSession({
    name: 'session',
    keys: ['!bwjkslkekhdfjlk$'],
    maxAge: 1 * 60 * 60 * 1000 // 1 hour
}));

app.use(passport.initialize());

const options = {
    // callbackURL: 'https://auw1xbwwy4.execute-api.eu-west-1.amazonaws.com/prod/auth/cognito/callback',
    callbackURL: 'http://localhost:3000/auth/cognito/callback',
    logoutCallbackURL: 'http://localhost:3000/login',
    clientDomain: 'https://api3.galesoftware.net',
    clientID: '5kluu0kr96sj93g78h8fueqhuq',
    state: 'statehere',
    // clientSecret: 'shhh-its-a-secret',
    region: 'eu-west-1'
};

function verify(accessToken, refreshToken, profile, done) {
    console.log(`Callback from the call to verify ${accessToken}, ${JSON.stringify(profile)}`);
    done(null, profile);
}

passport.use(new OAuth2CognitoStrategy(options, verify));

passport.serializeUser((user, done) => {
    console.log('user is in serialize' + JSON.stringify(user));
    return done(null, user);
});
passport.deserializeUser((obj, done) => {
    console.log('user is in deserialize' + JSON.stringify(obj));
    done(null, obj)
});

app.use(passport.session());

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
    console.log('Uswer: ', req.user);

    if (req.isAuthenticated()) {
        isBlah(req, res, next)
        console.log();
    }
    // console.log('is user:', JSON.stringify(req.user()));
    next();
})

router.get('/', (req, res) => {
  res.render('index', {
    apiUrl: req.apiGateway ? `https://${req.apiGateway.event.headers.Host}/${req.apiGateway.event.requestContext.stage}` : 'http://localhost:3000'
  })
})

router.get('/login',
    // passport.authenticate('oauth2-cognito')
    // passport.authenticate('cognito-oidc')
    passport.authenticate('cognito-oauth2')
);

router.get('/logout', function(req, res){
    req.logout();
    console.log(JSON.stringify(req.session) + ' and the user is ');
    res.redirect(`${options.clientDomain}/logout?logout_uri=${options.logoutCallbackURL}&client_id=${options.clientID}`);
});

app.get('/auth/cognito/callback',
    passport.authenticate('cognito-oauth2'),
    // passport.authenticate('cognito-oidc'),
function(req, res) {
        // Successful authentication, redirect home.
        console.log('successful authentication ' + JSON.stringify(req.session));
        console.log('am i auth:  ' + req.isAuthenticated());
        res.redirect('/profile');
    });

router.get('/sam1', function (req, res, next) {
    req.session.views = (req.session.views || 0) + 1
    console.log(JSON.stringify(req.session));
    res.end(req.session.views + ' views!')
})

router.get('/changePassword', (req, res) => {
    res.render('changePassword', {
        apiUrl: req.apiGateway ? `https://${req.apiGateway.event.headers.Host}/${req.apiGateway.event.requestContext.stage}` : 'http://localhost:3000'
    })})

router.get('/profile', isAuthenticated,
    (req, res) => {
    res.render('profile', {
        email: req.user.email,
        phone_number: req.user.phone_number
    })});


// // The aws-serverless-express library creates a server and listens on a Unix
// // Domain Socket for you, so you can remove the usual call to app.listen.
// // app.listen(3000)

app.use('/', router);

//
// Export your express server so you can import it in the lambda function.
module.exports = app;
