/**
 * Module dependencies.
 */
const util = require('util')
  , OAuth2Strategy = require('passport-oauth2')
  , AWS = require('aws-sdk');


/**
 * Creates an instance of `OAuth2Strategy`.
 *
 * The Cognito OAuth 2.0 authentication strategy authenticates requests using the OAuth
 * 2.0 framework and retrieves user data from AWS Cognito User Pools
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, refreshToken, profile, done) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 * Additional `info` can optionally be passed as a third argument, typically
 * used to display informational messages.  If an exception occured, `err`
 * should be set.
 *
 * Options:
 *  const clientDomain = ''; // https://innovation-dev.auth.us-west-2.amazoncognito.com
 *   - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *   - `clientDomain`      AWS Cognito user pool domain name
 *   - `clientID`          AWS Cognito user pool app client
 *   - `clientSecret`      AWS Cognito user pool app client secret
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *   - `region`            AWS Cognito user pool region
 *
 * Examples:
 *
 *     passport.use(new OAuth2CognitoStrategy({
 *         callbackURL: 'https://myapp.com/auth/cognito/callback',
 *         clientDomain: 'https://myapp.auth.us-west-2.amazoncognito.com',
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret',
 *         region: 'us-west-2'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */

function Strategy({clientDomain, clientID, clientSecret, callbackURL, passReqToCallback, region, state}, verify) {
  this.options = {
    authorizationURL: `${clientDomain}/oauth2/authorize`,
    userInfoURL: `${clientDomain}/oauth2/userInfo`,
      tokenURL: `${clientDomain}/oauth2/token`,
      clientID,
    clientSecret,
    callbackURL,
    // state,
    passReqToCallback
  };

  OAuth2Strategy.call(this, this.options, verify);
  
  AWS.config.region = region;
  
  this.cognitoClient = new AWS.CognitoIdentityServiceProvider();
  this.name = 'cognito-oauth2';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from AWS Cognito.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
// Strategy.prototype.userProfile = function(accessToken, done) {
//
//   this.cognitoClient.getUser({AccessToken: accessToken}, (err, userData) => {
//     if (err) {
//       return done(err, null);
//     }
//
//     const profile = {};
//
//     for (let i = 0; i < userData.UserAttributes.length; i++) {
//       const a = userData.UserAttributes[i];
//       profile[a.Name] = a.Value;
//     }
//       profile.accessToken = accessToken;
//
//     done(null, profile);
//   });
//
// }


Strategy.prototype.userProfile = function(accessToken, done) {
    this._oauth2.useAuthorizationHeaderforGET(true);
    this._oauth2.get(this.options.userInfoURL, accessToken, function (err, body, res) {
        if (err) { return done(new Error('failed to fetch user profile', err)); }

        try {
            var json = JSON.parse(body);
            const profile = {};
            profile.json = json;
            profile.accessToken = accessToken;
            // var profile = new Profile(json, body);

            done(null, profile);
        } catch(e) {
            done(e);
        }
    });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;