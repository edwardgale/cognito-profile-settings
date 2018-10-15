const jwksClient = require('jwks-rsa');
const jwt = require('jsonwebtoken');

module.exports = function(options) {
    return function(req, res, next) {
        console.log('kjsdf');
        if (req.isAuthenticated()) {
            // if request is authenticated then check validity of access token.
            const token = req.user.accessToken;
            const decodedToken = jwt.decode(token, {complete: true});
            const jwtPayload = decodedToken.payload;
            const jwtHeader = decodedToken.header;
            const iss = jwtPayload.iss;
            const jwksClient = jwksClient({
                jwksUri: `${iss}/.well-known/jwks.json`,
                cache: true,
                rateLimit: true,
            });
            jwksClient.getSigningKey(jwtHeader.kid, (err, key) => {
                if (err) { return next(new Error('failed to get the signing key', err)); }

                const signingKey = key.publicKey || key.rsaPublicKey;

                // verify token
                const decoded = jwt.verify(token, signingKey);

                return next();
            });
        } else {
            next();
        }

    }
};
