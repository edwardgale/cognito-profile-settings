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


const OAuth2Strategy = require('passport-oauth').OAuth2Strategy;

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
    callbackURL: 'https://auw1xbwwy4.execute-api.eu-west-1.amazonaws.com/prod/auth/cognito/callback',
    clientDomain: 'https://api3.galesoftware.net',
    clientID: '5kluu0kr96sj93g78h8fueqhuq',
    // clientSecret: 'shhh-its-a-secret',
    region: 'eu-west-1'
};


function verify(accessToken, refreshToken, profile, done) {
    console.log(`Callback from the call to verify ${accessToken}, ${JSON.stringify(profile)}`);



    done(null, profile);

    // User.findOrCreate(profile, (err, user) => {
    //     console.log('returning from user');
    //     done(err, user);
    // });
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
// passport.deserializeUser((obj, done) => done(null, obj));


app.get('/auth/cognito/callback',
    passport.authenticate('oauth2-cognito'),
    function(req, res) {
        // Successful authentication, redirect home.
        console.log('successful authentication ' + JSON.stringify(req.session));
        res.redirect('/prod');
    });

    // (req,res) => res.send(req.user)
// );


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

router.get('/auth/cognito',
    passport.authenticate('oauth2-cognito')
);

router.get('/', (req, res) => {
  res.render('index', {
    apiUrl: req.apiGateway ? `https://${req.apiGateway.event.headers.Host}/${req.apiGateway.event.requestContext.stage}` : 'http://localhost:3000'
  })
})

router.get('/sam', (req, res) => {
  res.sendFile(`${__dirname}/sam-logo.png`)
})

router.get('/sam1', function (req, res, next) {
    req.session.views = (req.session.views || 0) + 1
    res.end(req.session.views + ' views!')
})

router.get('/changePassword', (req, res) => {
    res.render('changePassword', {
        apiUrl: req.apiGateway ? `https://${req.apiGateway.event.headers.Host}/${req.apiGateway.event.requestContext.stage}` : 'http://localhost:3000'
    })})

router.get('/profile', (req, res) => {
    res.render('profile', {
        apiUrl: req.apiGateway ? `https://${req.apiGateway.event.headers.Host}/${req.apiGateway.event.requestContext.stage}` : 'http://localhost:3000'
    })})


// // The aws-serverless-express library creates a server and listens on a Unix
// // Domain Socket for you, so you can remove the usual call to app.listen.
// // app.listen(3000)

app.use('/', router)

//
// Export your express server so you can import it in the lambda function.
module.exports = app
