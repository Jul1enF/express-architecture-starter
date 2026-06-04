const User = require('../models/users.model')

const bcrypt = require('bcrypt')
const uid2 = require('uid2')
const jwt = require('jsonwebtoken')
const jwtTokenKey = process.env.JWT_TOKEN_KEY;
const { setWebTokens } = require("../utils/webTokens")


// SIGNIN
const signin = async (req, res, next) => {

    const { email, password } = req.body

    const userData = await User.findOne({ email })

    const correctLogin = !userData ? false : await bcrypt.compare(password, userData.password)

    if (!correctLogin) {
        res.json({ result: false, errorText: "Email ou mot de passe incorrect !" })
        return
    }
    else {
        const token = uid2(32)
        const newJwtToken = jwt.sign({
            token,
        }, jwtTokenKey)

        userData.token = token

        await userData.save()

        const mobileApp = req.headers['x-client-type'] === "mobile-app"

        if (!mobileApp) setWebTokens(res, newJwtToken)

        const user = {
            first_name: userData.first_name,
            is_admin: userData.is_admin
        }

        if (mobileApp) user.jwtToken = newJwtToken

        res.json({ result: true, user })
    }
}

module.exports = { signin }