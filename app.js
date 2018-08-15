const express = require('express')
const logger = require('morgan')
const passport = require('passport')
const BearerStrategy = require('passport-http-bearer').Strategy
const CustomStrategy = require('passport-custom').Strategy
const fetch = require('node-fetch')

const indexRouter = require('./routes/index')
const User = require('./routes/User')

const app = express();
// only set NO_AUTH to true for instances that aren't proxied
const noAuth = process.env.NO_AUTH === 'true' // require true, everything else is false

if(noAuth) {
  passport.use(new CustomStrategy(function(req, next) {
    const user = new User('anonymous', 'anonymous', 'anonymous', null, false)
    next(null, user);
  }))
} else {
  passport.use(new BearerStrategy(function(token, next) {
    fetch('http://oauth2:8080/identity/'+token, {
      method: 'GET',
      headers:{
        'accepts': 'application/json',
        'Cache-Control': 'no-store'
      }
    }).then(response => {
      if (!response.ok) {
        return next('not ok returned from oauth2server');
      }
      return response.json()
    }).then(data => {
      if(data) return User.isValid(data.id, next)
    }).catch(err => {
      return next(err)
    })

  }))
}

app.use(logger('dev'))
app.use(express.json())
app.use(express.urlencoded({ extended: false }))

app.use('/', indexRouter)

module.exports = app
