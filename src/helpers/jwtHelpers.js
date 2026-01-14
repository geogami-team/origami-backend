"use strict";

const config = require("config"),
  jwt = require("jsonwebtoken"),
  hashJWT = require("./jwtRefreshTokenHasher"),
  {
    addTokenToBlacklist,
    // addTokenHashToBlacklist,
    isTokenBlacklisted,
  } = require("./tokenBlacklist"),
  { v4: uuidv4 } = require("uuid"),
  moment = require("moment"),
  User = require("../models/user");
const { Error } = require("mongoose");

const {
  algorithm: jwt_algorithm,
  secret: jwt_secret,
  issuer: jwt_issuer,
  validity_ms: jwt_validity_ms,
} = config.get("jwt");

// refresh_token configuration
const refresh_token_validity_ms = config.get("refresh_token.validity_ms");

const jwtSignOptions = {
  algorithm: jwt_algorithm,
  issuer: jwt_issuer,
  expiresIn: Math.round(Number(jwt_validity_ms) / 1000),
};

const jwtVerifyOptions = {
  algorithms: [jwt_algorithm],
  issuer: jwt_issuer,
};

// creates a new jwt and refresh token pair for the given user
const createToken = function createToken(user) {
  const payload = { roles: user.roles },
    signOptions = Object.assign(
      { subject: user.email, jwtid: uuidv4() },
      jwtSignOptions
    );

  return new Promise(function (resolve, reject) {
    jwt.sign(payload, jwt_secret, signOptions, async (err, token) => {
      if (err) {
        return reject(err);
      }

      // JWT generation was successful
      // we now create the refreshToken.
      // and set the refreshTokenExpires to 1 week
      // it is a HMAC of the jwt string
      const newRefreshToken = hashJWT(token);
      try {
        // calculate new refresh token expiry date
        const newTokenData = {
          token: newRefreshToken,
          expires: new Date(Date.now() + Number(refresh_token_validity_ms))
        };

        // save refresh token and expiry as a list to user
        // This allows multiple devices to be logged in simultaneously
        user.refreshTokens = user.refreshTokens || [];
        user.refreshTokens.push(newTokenData);        
        await user.save();

        return resolve({ token, newRefreshToken });
      } catch (err) {
        return reject(err);
      }
    });
  });
};

const invalidateToken = function invalidateToken({
  user,
  _jwt,
  _jwtString,
} = {}) {
  createToken(user);
  addTokenToBlacklist(_jwt, _jwtString);
};

// refreshes a jwt using a valid refresh token
const refreshJwt = async function refreshJwt(refreshToken) {
  const user = await User.findOne({
    'refreshTokens.token': refreshToken,
    'refreshTokens.expires': { $gte: new Date() }
  });

  // if no user found, the refresh token is invalid or too old
  if (!user) {
    throw new Error(
      "Refresh token invalid or too old. Please sign in with your username and password."
    );
  }

  // Find and remove this specific token (rotate it)
  const tokenIndex = user.refreshTokens.findIndex(t => t.token === refreshToken);
  user.refreshTokens.splice(tokenIndex, 1);  // Remove old token

  // create new token pair
  const { token, newRefreshToken  } = await createToken(user);  // This now adds to array

  return Promise.resolve({ token, refreshToken: newRefreshToken, user });
};

const jwtInvalidErrorMessage =
  "Invalid JWT authorization. Please sign in to obtain new JWT.";

const verifyJwt = function verifyJwt(req, res, next) {
  // check if Authorization header is present
  const rawAuthorizationHeader = req.header("authorization");
  if (!rawAuthorizationHeader) {
    return res.status(401).send("Not Authorized");
  }

  const [bearer, jwtString] = rawAuthorizationHeader.split(" ");
  if (bearer !== "Bearer") {
    return res.status(401).send("Not Authorized");
  }

  jwt.verify(
    jwtString,
    jwt_secret,
    jwtVerifyOptions,
    function (err, decodedJwt) {
      if (err) {
        return res.status(401).send("Not Authorized");
      }

      // check if the token is blacklisted by performing a hmac digest on the string representation of the jwt.
      // also checks the existence of the jti claim
      if (isTokenBlacklisted(decodedJwt, jwtString)) {
        return res.status(401).send("Not Authorized");
      }

      User.findOne({
        email: decodedJwt.sub.toLowerCase(),
        roles: decodedJwt.roles,
      })
        .exec()
        .then(function (user) {
          if (!user) {
            throw new Error();
          }

          req.user = user;
          req._jwt = decodedJwt;
          req._jwtString = jwtString;

          return next();
        })
        .catch(function () {
          return res.status(401).send("Not Authorized");
        });
    }
  );
};

module.exports = {
  createToken,
  invalidateToken,
  refreshJwt,
  verifyJwt,
};
