const User = require('../models/users.model')

const bcrypt = require('bcrypt')
const uid2 = require('uid2')
const jwt = require('jsonwebtoken')
const jwtTokenKey = process.env.JWT_TOKEN_KEY;

const fakeHash = "$7b$90$8TKRDLyb/bLJ8c9iDk6Gs.urerUoVogSEGrzBvwsfeRj/IZRTcCyQC"

// SIGNIN
const signin = async (req, res, next) => {

    const { email, password } = req.body

    const userData = await User.findOne({ email })

    const comparisonHash = userData?.password ?? fakeHash

    const correctLogin = await bcrypt.compare(password, comparisonHash)

    if (!userData || !correctLogin) {
        res.json({ result: false, errorText: "Email ou mot de passe incorrect !" })
        return
    }

    const token = uid2(32)
    const newJwtToken = jwt.sign({
        token,
    }, jwtTokenKey)

    userData.token = token

    await userData.save()

    const user = {
        isConnected: true,
        first_name: userData.first_name,
        last_name: userData.last_name,
        email: userData.email,
        is_admin: userData.is_admin
    }

    const successResponse = { result: true, user, jwtToken: newJwtToken }

    res.json(successResponse)
}

module.exports = { signin }