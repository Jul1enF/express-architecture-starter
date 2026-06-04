var express = require('express');
var router = express.Router();

const { errorHandler } = require('../utils/errorHandler')
const { requireAdmin, requireUser } = require('../middlewares/token-auth.middleware')

const { signin } = require('../controllers/auth.controller')
const { updateUser } = require ('../controllers/users-modifications.controller')


// SIGNIN
router.post('/signin', errorHandler(signin));

// UPDATE USER
router.put('/update-user', requireUser, errorHandler(updateUser))

module.exports = router;
