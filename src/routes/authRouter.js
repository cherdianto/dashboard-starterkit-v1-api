import express from 'express'
import verifyToken from '../middlewares/verifyToken.js'
import { register, login, logout, refreshToken, changePassword, getUser, resetPassword, validateResetLink, updateProfile } from '../controllers/authController.js'
const router = express.Router()

router.post('/register', register)
router.post('/login', login)
router.put('/update-profile', verifyToken, updateProfile)
// router.get('/change-password', verifyToken, changePassword)
// router.get('/user', verifyToken, getUser)
// router.get('/logout', logout)
// router.get('/reset-password', resetPassword)
// router.get('/rst', validateResetLink)
// router.get('/refreshToken', refreshToken)
// router.post('/change-password', verifyToken, changePassword)

export default router