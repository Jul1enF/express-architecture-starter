const jwt = require("jsonwebtoken");
const jwtTokenKey = process.env.JWT_TOKEN_KEY;
const User = require("../models/users.model");
const verifyCsrfToken = require("../utils/webTokens")

const errorResponse = {
  result: false,
  sessionExpired: true,
  errorText: "Session invalide ou expirée. Merci de réessayer après vous être reconnecté(e).",
}


const userTokenAuth = async (req, res, next) => {
  try {
    const mobileApp = req.headers['x-client-type'] === "mobile-app"
    const csrfTokenHeader = req.headers['x-csrf-token']
    const csrfTokenCookie = req.cookies.csrfToken

    if (!mobileApp) {
      const validCsrf =
        verifyCsrfToken(csrfTokenHeader) &&
        csrfTokenCookie &&
        csrfTokenHeader === csrfTokenCookie

      if (!validCsrf) {
        return res.json(errorResponse)
      }
    }

    const { authorization } = req.headers;

    const jwtToken = mobileApp ? authorization.slice(7, authorization.length) : req.cookies.jwtToken

    if (!jwtToken) {
      return res.json(errorResponse)
    }

    const { token } = jwt.verify(jwtToken, jwtTokenKey);

    req.user = await User.findOne({ token });

    // Check that the user token has been successfuly found in the db
    if (!req.user) {
      return res.json(errorResponse);
    }

    return next();
  } catch (err) {
    console.log("User Token Auth Error :", err);
    return res.json(errorResponse);
  }
};


const adminTokenAuth = async (req, res, next) => {
  try {
    const mobileApp = req.headers['x-client-type'] === "mobile-app"
    const csrfTokenHeader = req.headers['x-csrf-token']
    const csrfTokenCookie = req.cookies.csrfToken

    if (!mobileApp) {
      const validCsrf =
        verifyCsrfToken(csrfTokenHeader) &&
        csrfTokenCookie &&
        csrfTokenHeader === csrfTokenCookie

      if (!validCsrf) {
        return res.json(errorResponse)
      }
    }

    const { authorization } = req.headers;

    const jwtToken = mobileApp ? authorization.slice(7, authorization.length) : req.cookies.jwtToken

    if (!jwtToken) {
      return res.json(errorResponse)
    }

    const { token } = jwt.verify(jwtToken, jwtTokenKey);

    req.user = await User.findOne({ token });

    // Check that the user token has been successfuly found in the db
    if (!req.user || !req.user?.is_admin) {
      return res.json(errorResponse);
    }

    return next();
  } catch (err) {
    console.log("User Token Auth Error :", err);
    return res.json(errorResponse);
  }
};

module.exports = { userTokenAuth, adminTokenAuth };