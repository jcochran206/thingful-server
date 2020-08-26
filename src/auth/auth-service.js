const bcrypt = require('bcrypt');
const config = require('../config')

const AuthService = {
    getUserWithUserName(db, user_name) {
      return db('thingful_users')
        .where({ user_name })
        .first()
    },
    parseBasicToken(token) {
      return Buffer
        .from(token, 'base64')
        .toString()
        .split(':')
    },
    comparePasswords(password, hash){
      return bcrypt.compare(password, hash)
    }
  }
  
  module.exports = AuthService