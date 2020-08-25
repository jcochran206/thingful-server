const bcrypt = require('bcrypt')
const AuthService = require('../auth/auth-service')

function requireAuth(req, res, next) {
  const authToken = req.get('Authorization') || ''
  // console.log(authToken, 'capture auth')
  let basicToken
  if (!authToken.toLowerCase().startsWith('basic ')) {
    return res.status(401).json({ error: 'Missing basic token' })
  } else {
    basicToken = authToken.slice('basic '.length, authToken.length)
  }
  // console.log(basicToken, 'get token here')
  const [tokenUserName, tokenPassword] = AuthService.parseBasicToken(basicToken)
  
  if (!tokenUserName || !tokenPassword) {
    return res.status(401).json({ error: 'Unauthorized request token or password not setup' })
  }
  // console.log(tokenUserName, tokenPassword, 'token user and pass');
  AuthService.getUserWithUserName(
    req.app.get('db'),
    tokenUserName
  )
    .then(user => {
      console.log(user, 'user from database')
      if (!user || user.password !== tokenPassword) {
        return res.status(401).json({ error: 'Unauthorized request user not found in database' })
      }

      next()
    })
    .catch(next)
}

module.exports = {
  requireAuth,
}