const express = require('express')
const router = express.Router()
const User = require('./User')
const bcrypt = require('bcrypt')

const returnStatus = (res, err) => {
  console.log('in returnStatus err = ' + JSON.stringify(err))
  var code = 400
  res.status(code).send(err)
}

/* GET list of users */
router.get('/users', (req, res) => {
  User.getAllUsers((err, ids) => {
    if(err) return returnStatus(res, err)
    return res.send(ids)
  })
})
/* GET specific user */
router.get('/users/:user', (req, res) => {
  User.isValid(req.params.user, (err, user) => {
    if(err) return returnStatus(res, err)
    if(!user) return res.status(404).send('user not found')
    user.hash = null
    return res.send(user)
  })
})
/* create new user */
router.post('/users', (req, res) => {
  if(!req.body.password) return res.status(400).send('password is required')
  bcrypt.hash(req.body.password, 10, (err, hash) => {
    if(!req.body.username) return res.status(400).send('username is required')
    const user = new User(req.body.username,req.body.fullname,req.body.email,hash,true)
    user.saveUser(err => {
      if(err) return returnStatus(res, err)
      user.hash = null
      res.status(201).send(user)
    })
  })
})

module.exports = router