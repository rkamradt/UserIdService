const express = require('express')
const router = express.Router()
const User = require('./User')
const bcrypt = require('bcrypt')
const passport = require('passport')

const returnStatus = (res, err) => {
  console.log('in returnStatus err = ' + JSON.stringify(err))
  var code = 400
  res.status(code).send(err)
}

// only set NO_AUTH to true for instances that aren't proxied
const authenticate = process.env.NO_AUTH === 'true' ?
  passport.authenticate('custom', { session: false }) :
  passport.authenticate('bearer', { session: false })  // require true, everything else is false

/* GET list of users */
router.get('/users', authenticate, (req, res) => {
  // todo check authenticated for admin role
  User.getAllUsers((err, ids) => {
    if(err) return returnStatus(res, err)
    return res.send(ids)
  })
})
/* GET specific user */
router.get('/users/:user', authenticate, (req, res) => {
  if(process.env.NO_AUTH !== 'true' && req.user.username !== req.params.user) return res.status(403).send('Forbidden')
  User.isValid(req.params.user, (err, user) => {
    if(err) return returnStatus(res, err)
    if(!user) return res.status(404).send('user not found')
    user.hash = null
    return res.send(user)
  })
})
/* GET specific user (password verified) */
router.get('/users/:user/confirm', (req, res) => {
  if(!req.headers.password) return res.status(400).send('password is required')
  if(!req.params.user) return res.status(400).send('username is required')
  User.isValid(req.params.user, (err, user) => {
    if(err) return returnStatus(res, err)
    if(!user) return res.status(404).send('user not found')
    bcrypt.compare(req.headers.password, user.hash, (err, match) => {
      if(err) return res.status(500).send('error comparing hash')
      if(!match) return res.status(403).send('unconfirmed')
      user.hash = null;
      return res.send(user)
    })
  })
})
/* create new user */
router.post('/users', (req, res) => {
  if(!req.body.password) return res.status(400).send('password is required')
  if(!req.body.username) return res.status(400).send('username is required')
  User.isValid(req.body.username, (err, user) => {
    if(err) return res.status(500).send('error looking up user')
    if(user) return res.status(400).send('user already exists')
    bcrypt.hash(req.body.password, 10, (err, hash) => {
      if(err) return res.status(500).send('error creating hash')
      const user = new User(req.body.username,req.body.fullname,req.body.email,hash,true)
      user.saveUser(err => {
        if(err) return returnStatus(res, err)
        user.hash = null
        res.status(201).send(user)
      })
    })
  })
})

router.post('/users/:user/validate', authenticate, (req, res) => {
  // todo check authenticated for admin role
  User.isValid(req.params.user, (err, user) => {
    if(err) return returnStatus(res, err)
    if(!user) return res.status(404).send('user not found')
    user.tentative = false;
    user.saveUser(err => {
      if(err) return returnStatus(res, err)
      user.hash = null
      res.status(201).send(user)
    })
  })
})


module.exports = router
