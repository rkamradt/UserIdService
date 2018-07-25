const Redis = require('ioredis')

const client = new Redis(6379, 'redis')
const userKey = 'users:'

module.exports = class User {
  constructor(username, fullname, email, hash, tentative) {
    this.username = username
    this.fullname = fullname
    this.email = email
    this.hash = hash
    this.tentative = tentative;
  }
  saveUser(next) {
    const user = this
    client.set(userKey + user.username, JSON.stringify(user))
    return next(null);
  }
  static isValid(userId, next) {
    client.get(userKey + userId, (err, data) => {
      if(err) return next(err)
      if(!data) return next("not found")
      data = JSON.parse(data)
      const user = new User(data.username, data.fullname, data.email, data.hash, data.tentative)
      return next(null, user)
    })
  }
  static getAllUsers(next) {
    client.keys(userKey + '*', next)
  }
}
