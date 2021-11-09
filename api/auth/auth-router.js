const express = require('express')
const router = express.Router()
const bcrypt = require('bcryptjs')

const User = require('../users/users-model')

const {
  checkUsernameFree,
  checkUsernameExists,
  checkPasswordLength
} = require('./auth-middleware')



router.post('/register', checkUsernameFree, checkPasswordLength, async (req, res, next) => {
  
    const { username, password } = req.body
    // NEVER STORE PLAIN TEXT PASSWORDS IN DB!
    const hash = bcrypt.hashSync(password, 6) // 2 ^ 6
    const newUser = { username, password: hash }
  await User.add(newUser)
    .then(user => {
      res.status(201).json(user)
  }) .catch(next)
})
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post('/login', checkUsernameExists, async (req, res, next) => {
  try {
    const { username, password } = req.body
    const [user] = await User.findBy({ username })
    if (!user) { // TEST THIS
      return next({ status: 401, message: 'Invalid credentials' })
    }
    const doesPasswordCheck = bcrypt.compareSync(password, user.password)
    if (!doesPasswordCheck) { // TEST THIS
      return next({ status: 401, message: 'Invalid credentials' })
    }
    // add a key to req.session to trigger the session into being stored, cookie sent...
    req.session.user = user // creates & stores the session, sets SET-COOKIE with sid...
    res.json({ message: `welcome, ${user.username}` })
  } catch (err) {
    next(err)
  }
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */

// router.get('/logout', restricted, (req, res, next) => {
  
// })
/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */

 module.exports = router;

// Don't forget to add the router to the `exports` object so it can be required in other modules
