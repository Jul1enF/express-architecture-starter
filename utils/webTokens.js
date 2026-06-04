const crypto = require("crypto")
const csrfTokenKey = process.env.CSRF_TOKEN_KEY

const createCsrfToken = () => {
    const random = crypto.randomBytes(32).toString('hex')
    const signature = crypto
        .createHmac('sha256', csrfTokenKey)
        .update(random)
        .digest('hex')

    return `${random}.${signature}`
}

exports.setWebTokens = (res, jwtToken) => {

    const isLocal = process.env.NODE_ENV === 'local'

    const csrfToken = createCsrfToken()

    const cookieOptions = {
        secure: !isLocal,
        sameSite: isLocal ? 'lax' : 'none',
        path: '/', // entry point of the cookie => if '/auth' the cookie will only be available in pages with /auth suffix in url
        maxAge: 1000 * 60 * 60 * 24 * 50, // 50 days
    }

    res.cookie('jwtToken', jwtToken, {
        ...cookieOptions,
        httpOnly: true,
    })

    res.cookie('csrf-token', csrfToken, {
        ...cookieOptions,
        httpOnly: false,
    })
}

const safeCompare = (a, b) => {
  const bufferA = Buffer.from(a)
  const bufferB = Buffer.from(b)

  // timingSafeEqual below will crash if the sizes are different
  if (bufferA.length !== bufferB.length) {
    return false
  }

  return crypto.timingSafeEqual(bufferA, bufferB)
}


exports.verifyCsrfToken = (csrfToken) => {
    if (!csrfToken) return false

    const parts = csrfToken.split('.')
    if (parts.length !== 2) return false

    const [random, signature] = parts

    if (!random || !signature) return false

    const expected = crypto
      .createHmac('sha256', csrfTokenKey)
      .update(random)
      .digest('hex')

    return safeCompare(signature, expected)
}