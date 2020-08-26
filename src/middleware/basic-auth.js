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
      //console.log(user, 'user from database')
      if(!user) {
        return res.status(401).json({ errror: 'Unauthorized request'})
      }
      return AuthService.comparePasswords(tokenPassword, user.password)
      .then(passwordsMatch => {
        if(!passwordsMatch){
          return res.status(401).json({error: 'unauthorized request'})
        }
        req.user = user
        next()
      })
    })
    .catch(next)
}

module.exports = {
  requireAuth,
}