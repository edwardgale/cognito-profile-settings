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
const passport = require('passport')
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

// passport.use('provider', new OAuth2Strategy({
//     authorizationURL: 'https://www.provider.com/oauth2/authorize',
//     tokenURL: 'https://www.provider.com/oauth2/token',
//     clientID: '123-456-789',
//     clientSecret: 'shhh-its-a-secret',
//     callbackURL: 'https://www.example.com/auth/provider/callback'
//   },
//   function(accessToken, refreshToken, profile, done) {
//     User.findOrCreate(..., function(err, user) {
//       done(err, user);
//     });
//   }
// ));

app.get('/auth/provider', passport.authenticate('provider'));

app.set('view engine', 'njk');
// app.set('view engine', 'pug')

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

router.get('/', (req, res) => {
  res.render('index', {
    apiUrl: req.apiGateway ? `https://${req.apiGateway.event.headers.Host}/${req.apiGateway.event.requestContext.stage}` : 'http://localhost:3000'
  })
})

router.get('/sam', (req, res) => {
  res.sendFile(`${__dirname}/sam-logo.png`)
})

router.get('/changePassword', (req, res) => {
    res.render('changePassword', {
        apiUrl: req.apiGateway ? `https://${req.apiGateway.event.headers.Host}/${req.apiGateway.event.requestContext.stage}` : 'http://localhost:3000'
    })})

// router.get('/users', (req, res) => {
//   res.json(users)
// })
//
// router.get('/users/:userId', (req, res) => {
//   const user = getUser(req.params.userId)
//
//   if (!user) return res.status(404).json({})
//
//   return res.json(user)
// })
//
// router.post('/users', (req, res) => {
//   const user = {
//     id: ++userIdCounter,
//     name: req.body.name
//   }
//   users.push(user)
//   res.status(201).json(user)
// })
//
// router.put('/users/:userId', (req, res) => {
//   const user = getUser(req.params.userId)
//
//   if (!user) return res.status(404).json({})
//
//   user.name = req.body.name
//   res.json(user)
// })
//
// router.delete('/users/:userId', (req, res) => {
//   const userIndex = getUserIndex(req.params.userId)
//
//   if (userIndex === -1) return res.status(404).json({})
//
//   users.splice(userIndex, 1)
//   res.json(users)
// })
//
// const getUser = (userId) => users.find(u => u.id === parseInt(userId))
// const getUserIndex = (userId) => users.findIndex(u => u.id === parseInt(userId))
//
// // Ephemeral in-memory data store
// const users = [{
//   id: 1,
//   name: 'Joe'
// }, {
//   id: 2,
//   name: 'Jane'
// }]
// let userIdCounter = users.length
//
// // The aws-serverless-express library creates a server and listens on a Unix
// // Domain Socket for you, so you can remove the usual call to app.listen.
// // app.listen(3000)
app.use('/', router)
//
// Export your express server so you can import it in the lambda function.
module.exports = app
