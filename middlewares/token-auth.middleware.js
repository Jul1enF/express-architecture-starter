const jwt = require("jsonwebtoken");
const jwtTokenKey = process.env.JWT_TOKEN_KEY;
const User = require("../models/users.model");

const errorResponse = {
  result: false,
  sessionExpired: true,
  errorText: "Session invalide ou expirée. Merci de réessayer après vous être reconnecté(e).",
}


const tokenAuth = (requireAdmin = false) => {
  return async (req, res, next) => {
    try {
      
      const { authorization } = req.headers;

      const jwtToken = authorization?.startsWith('Bearer ') ? authorization.slice(7) : null

      if (!jwtToken) {
        return res.json(errorResponse)
      }

      const { token } = jwt.verify(jwtToken, jwtTokenKey);

      req.user = await User.findOne({ token });

      // Check that the user token has been successfuly found in the db
      if (!req.user || (requireAdmin && !req.user?.is_admin)) {
        return res.json(errorResponse);
      }

      return next();
    } catch (err) {
      console.log("User Token Auth Error :", err);
      return res.json(errorResponse);
    }
  };
}

const requireUser = tokenAuth()
const requireAdmin = tokenAuth(true)

module.exports = { requireUser, requireAdmin };