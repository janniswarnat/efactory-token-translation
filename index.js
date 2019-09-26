const config = require('./config');
const app = require('express')();
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const getPem = require('rsa-pem-from-mod-exp');

app.use(bodyParser.json());

app.get('/', async (req, res) => {
        console.log('req.headers:', req.headers);

        if (req.headers.authorization) {
            console.log('req.headers.authorization:', req.headers.authorization);
            let headerStrings = req.headers.authorization.split(' ');
            let token;
            if (headerStrings.length === 2) {
                if (headerStrings[0] === 'Bearer' || headerStrings[0] === 'bearer') {
                    token = headerStrings[1];
                }
            }

            if (token) {
                console.log('token', token);

                let pem = getPem(config.openid_connect_providers.default.realm_public_key_modulus, config.openid_connect_providers.default.realm_public_key_exponent);
                console.log('generated pem: ' + pem,);
                let decoded;
                try {
                    decoded = jwt.verify(token, pem, {
                        audience: config.openid_connect_providers.default.audience,
                        issuer: config.openid_connect_providers.default.issuer,
                        ignoreExpiration: false
                    });
                } catch (err) {
                    console.log('Access token is invalid', {
                        errorName: err.name,
                        errorMessage: err.message
                    });
                    res.status(200).send("Access token is invalid: " + err.message);
                    return;
                }
                res.status(200).send("Access token is fine");
                return;

            } else {
                res.status(400).send("No bearer token provided in authorization header");
                return;
            }


        } else {
            res.status(400).send("No authorization header provided in request");
            return;
        }
    }
);

app.listen(8080, () => {
    console.log('express-app started');
});
