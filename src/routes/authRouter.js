import express from 'express'
import verifyToken from '../middlewares/verifyToken.js'
import { register, login, logout, refreshToken, changePassword, getUser, resetPassword, validateResetLink, updateProfile } from '../controllers/authController.js'
import { loginFailedLimiter, passwordResetLimiter } from '../libraries/rateLimiter.js'
const router = express.Router()

router.post('/register', register)
router.post('/login', loginFailedLimiter, login)
router.put('/update-profile', verifyToken, updateProfile)
router.get('/logout', logout)
router.post('/change-password', verifyToken, changePassword)
router.get('/refresh-token', refreshToken)
router.get('/user', verifyToken, getUser)
router.get('/reset-password', passwordResetLimiter, resetPassword)
// router.get('/rst', validateResetLink)
// router.post('/change-password', verifyToken, changePassword)

export default router