import bcrypt from 'bcrypt'
import asyncHandler from 'express-async-handler'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import crypto from 'crypto'
import User from "../models/User.js"
import Token from "../models/Token.js"

const env = dotenv.config().parsed
const accessSecretKey = env.ACCESS_TOKEN_SECRET
const refreshSecretKey = env.REFRESH_TOKEN_SECRET
const accessExpiry = env.ACCESS_EXPIRY
const refreshExpiry = env.REFRESH_EXPIRY

function generateToken() {
    const buffer = crypto.randomBytes(32);
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

const generateAccessToken = (payload) => {
    return jwt.sign(payload, accessSecretKey, {
        expiresIn: accessExpiry
    })
}

const generateRefreshToken = (payload) => {
    return jwt.sign(payload, refreshSecretKey, {
        expiresIn: refreshExpiry
    })
}

// OK
// REGISTER : register new user
// endpoint : /api/auth/register
// method : post
// req.body : nama, nim, email, whatsapp, password, confirmPassword
// error output :
// -- status : 400 
// -- message : NAMA_REQUIRED, NIM_REQUIRED, EMAIL_REQUIRED, WHATSAPP_REQUIRED, PASSWORD_REQUIRED, CONFIRM_PASSWORD_REQUIRED, DUPLICATE_EMAIL, DUPLICATE_WHATSAPP
// -- status : 500
// -- message : REGISTER_FAILED
// success : 
// -- status : true,
// -- message : REGISTER_SUCCESS
export const register = asyncHandler(async (req, res) => {
    const {
        nama,
        nim,
        email,
        whatsapp,
        password,
        confirmPassword
    } = req.body

    // check the req.body
    if (!nama) {
        res.status(400)
        throw new Error('NAMA_REQUIRED')
    }

    if (!email) {
        res.status(400)
        throw new Error('EMAIL_REQUIRED')
    }

    if (!whatsapp) {
        res.status(400)
        throw new Error('WHATSAPP_REQUIRED')
    }

    if (!password) {
        res.status(400)
        throw new Error('PASSWORD_REQUIRED')
    }

    if (!confirmPassword) {
        res.status(400)
        throw new Error('CONFIRM_PASSWORD_REQUIRED')
    }

    if (password !== confirmPassword) {
        res.status(400)
        throw new Error('PASSWORDS_MISMATCH')
    }

    const emailExist = await User.findOne({
        email
    })
    if (emailExist) {
        res.status(400)
        throw new Error('DUPLICATE_EMAIL')
    }

    const nimExist = await User.findOne({
        nim
    })
    if (nimExist) {
        res.status(400)
        throw new Error('DUPLICATE_NIM')
    }

    const whatsappExist = await User.findOne({
        whatsapp
    })
    if (whatsappExist) {
        res.status(400)
        throw new Error('DUPLICATE_WHATSAPP')
    }

    // MAKE SALT & PASSWORD HASHING
    let salt = await bcrypt.genSalt(12)
    let hashedPassword = await bcrypt.hash(password, salt)

    // STORE DATA TO DB
    try {
        const newUser = await User.create({
            nama,
            nim,
            email,
            whatsapp,
            password: hashedPassword
        })

        res.status(200).json({
            status: true,
            message: 'REGISTER_SUCCESS'
        })

    } catch (error) {
        res.status(500)
        throw new Error('REGISTER_FAILED')
    }
})

// OK
// @desc    LOGIN by registered user
// @route   POST /auth/login
// @access  Public
export const login = asyncHandler(async (req, res) => {
    const {
        email,
        password
    } = req.body

    // check the req.body
    if (!email) {
        res.status(400)
        throw new Error('EMAIL_REQUIRED')
    }

    if (!password) {
        res.status(400)
        throw new Error('PASSWORD_REQUIRED')
    }

    // user exist?
    const user = await User.findOne({
        email
    })
    if (!user) {
        res.status(400)
        throw new Error("EMAIL_NOT_FOUND")
    }

    // password match?
    const isMatch = bcrypt.compareSync(password, user.password)
    if (!isMatch) {
        res.status(400)
        throw new Error("WRONG_PASSWORD")
    }

    // next, generate tokens (access & refresh)
    const accessToken = generateAccessToken({
        id: user._id
    })

    const refreshToken = generateRefreshToken({
        id: user._id
    })

    // store refreshToken to database
    const updateDb = await User.findOneAndUpdate({
        _id: user._id
    }, {
        $set: {
            refreshToken,
            accessToken
        }
    }).select('-password -salt -refreshToken')

    if (!updateDb) {
        res.status(500)
        throw new Error("ERROR_UPDATE_DB")
    }

    // if updateDB success, then set cookies 
    if (env.ENV === 'dev') {
        res.cookie('refreshToken', refreshToken, {
            maxAge: 1 * 24 * 60 * 60 * 1000,
            httpOnly: true
        })
    } else {
        res.cookie('refreshToken', refreshToken, {
            maxAge: 1 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            domain: env.COOKIE_OPTION_PROD_URL,
            path: '/'
        })
    }

    res.status(200).json({
        status: true,
        message: "LOGIN_SUCCESS",
        user: updateDb
    })
})

// OKE
// @desc    Edit user profile by user
// @route   POST /auth/update-profile
// @access  Protected, need accessToken
export const updateProfile = asyncHandler(async (req, res) => {
    const {
        nama,
        email,
        whatsapp,
        alamat,
        tanggalLahir,
        tempatLahir,
        jurusan
    } = req.body

    const userId = req.user._id

    // check the req.body
    if (!nama) {
        res.status(400)
        throw new Error('NAMA_REQUIRED')
    }

    if (!email) {
        res.status(400)
        throw new Error('EMAIL_REQUIRED')
    }

    if (!whatsapp) {
        res.status(400)
        throw new Error('WHATSAPP_REQUIRED')
    }

    if (!alamat) {
        res.status(400)
        throw new Error('ALAMAT_REQUIRED')
    }

    if (!tempatLahir) {
        res.status(400)
        throw new Error('TEMPAT_LAHIR_REQUIRED')
    }

    if (!tanggalLahir) {
        res.status(400)
        throw new Error('TANGGAL_LAHIR_REQUIRED')
    }

    if (!jurusan) {
        res.status(400)
        throw new Error('JURUSAN_REQUIRED')
    }

    if (whatsapp != req.user.whatsapp) {
        const whatsappExist = await User.findOne({
            whatsapp
        })

        if (whatsappExist) {
            res.status(400)
            throw new Error('DUPLICATE_WHATSAPP')
        }
    }

    if (email != req.user.email) {
        const emailExist = await User.findOne({
            email
        })

        if (emailExist) {
            res.status(400)
            throw new Error('DUPLICATE_EMAIL')
        }
    }

    // store user info to DB
    try {
        const newUser = await User.findByIdAndUpdate(userId, {
            $set: {
                nama,
                email,
                whatsapp,
                alamat,
                tanggalLahir,
                tempatLahir,
                jurusan
            }
        }, {
            new: true
        }).select('-password -salt -refreshToken')

        res.status(200).json({
            status: true,
            message: 'UPDATE_PROFILE_SUCCESS',
            user: newUser
        })

    } catch (error) {
        res.status(500)
        // console.log(error)
        throw new Error('USER_REGISTER_FAILED')
    }
})

// OK
// @desc    logout by user
// @route   GET /auth/logout
// @access  Public
export const logout = asyncHandler(async (req, res) => {
    const userRefreshToken = req.cookies.refreshToken
    console.log(req.cookies)

    if (!userRefreshToken) {
        res.status(204)
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            domain: env.COOKIE_OPTION_PROD_URL,
            path: '/'
        })
        // throw new Error("NO_REFRESH_TOKEN")
        return res.status(200).json({
            status: true,
            message: "LOGGED_OUT_SUCCESS_1"
        })
    }

    jwt.verify(userRefreshToken, refreshSecretKey, async (error, decoded) => {

        if (env.ENV === 'dev') {
            res.clearCookie('refreshToken')
        } else {
            res.clearCookie('refreshToken', {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                domain: env.COOKIE_OPTION_PROD_URL,
                path: '/'
            })
        }

        if (error) {
            res.status(401)
            throw new Error("INVALID_REFRESH_TOKEN")
        }

        const user = await User.findById(decoded.id)

        if (!user) {
            res.status(401)
            throw new Error("USER_NOT_FOUND")
        }

        // update database
        const updateDb = await User.updateOne({
            _id: user._id
        }, {
            $set: {
                refreshToken: '',
                accessToken: ''
            }
        })

        if (!updateDb) {
            res.status(500)
            throw new Error("LOG_OUT_FAILED")
        }

        return res.status(200).json({
            status: true,
            message: "LOGGED_OUT_SUCCESS"
        })
    })

})

// OK
// @desc    change password by user
// @route   POST /auth/change-password
// @access  Protected
export const changePassword = asyncHandler(async (req, res) => {
    // form : email, oldpassword, newpassword

    const {
        oldPassword,
        newPassword
    } = req.body

    const user = req.user

    if (!newPassword || newPassword == '') {
        res.status(400)
        throw new Error("NEW_PASSWORD_REQUIRED")
    }

    if (newPassword.trim().length === 0 || newPassword.includes(" ")) {
        res.status(400)
        throw new Error("PASSWORD_CONTAIN_SPACE")
    }

    const isMatch = bcrypt.compareSync(oldPassword, user.password)
    if (!isMatch) {
        res.status(400)
        throw new Error("WRONG_PASSWORD")
    }

    // make salt
    let salt = await bcrypt.genSalt(12)
    // hash the password
    let hashedPassword = await bcrypt.hash(newPassword, salt)

    // update db
    const updateDb = await User.updateOne({
        _id: user._id
    }, {
        $set: {
            password: hashedPassword
        }
    })

    if (!updateDb) {
        res.status(500)
        throw new Error("PASSWORD_CHANGE_FAILED")
    }

    res.status(200).json({
        status: true,
        message: "PASSWORD_CHANGE_SUCCESS"
    })
})

// OK
// @desc    change password by user
// @route   GET /auth/refresh-token
// @access  Public
export const refreshToken = asyncHandler(async (req, res) => {
    const userRefreshToken = req.cookies.refreshToken

    if (!userRefreshToken) {
        res.status(401)
        throw new Error("REFRESH_TOKEN_NOT_FOUND")
    }

    jwt.verify(userRefreshToken, refreshSecretKey, async (error, decoded) => {
        if (error) {
            res.status(401)
            throw new Error("INVALID_REFRESH_TOKEN")
        }

        const user = await User.findById(decoded.id)

        if (!user) {
            res.status(401)
            throw new Error("USER_NOT_FOUND")
        }

        const accessToken = generateAccessToken({
            id: user._id
        })

        res.status(200).json({
            status: true,
            accessToken
        })

    })
})

// OK
// @desc    get user data by user
// @route   GET /auth/user
// @access  Protected
export const getUser = asyncHandler(async (req, res) => {
    const userId = req.user._id
    const user = await User.findById(userId).select('-password -refreshToken')

    res.status(200).json({
        status: true,
        message: "GET_USER_SUCCESS",
        user
    })
})

// OK
// @desc    generate link to reset password by user
// @route   GET /auth/reset-password?email=user@email.com
// @access  Public
export const resetPassword = asyncHandler(async (req, res) => {
    const email = req.query.email

    if (!email) {
        res.status(400)
        throw new Error("EMAIL_REQUIRED")
    }

    const user = await User.findOne({
        email
    })
    if (!user) {
        res.status(400)
        throw new Error("USER_NOT_FOUND")
    }

    let expiryAt = new Date()
    expiryAt.setMinutes(expiryAt.getMinutes() + 15)

    const newToken = await Token.create({
        email,
        token: generateToken(),
        expiryAt
    })

    if (!newToken) {
        res.status(400)
        throw new Error("RESET_LINK_FAILED")
    }

    // sending email to email client
    // const sendEmail = await gmailSend({
    //     to: email,
    //     subject: 'Password Reset Request',
    //     html: `<p>Berikut link untuk melakukan pengubahan password</p><p></p><p>${apiUrl}/auth/rst?token=${newToken.token}</p><p>Berlaku 15 menit</p><p></p><p>Abaikan jika Anda tidak melakukan permintaan permohonan pengubahan password.</p>`
    // })

    // if(sendEmail === 'error')
    // {
    //     res.status(400)
    //     throw new Error('SEND EMAIL FAILED')
    // }

    res.status(200).json({
        status: true,
        message: "RESET_LINK_SUCCESS",
        // token: newToken
    })
})


// OK
// @desc    get the form for reset password
// @route   GET /auth/rst?token=skdjfhaslkjdfasdfasidh0923siodfasd
// @access  Public
export const validateResetLink = asyncHandler(async (req, res) => {
    const token = req.query.token

    const isValid = await Token.findOne({token})

    if(!isValid){
        res.status(400)
        return res.render('tokenExpired')
        // throw new Error("INVALID_TOKEN OR HAS BEEN USED")
    }

    if(new Date(isValid.expiryAt) < Date.now()){
        res.status(400)
        return res.render('tokenExpired')
    }

    res.render('inputPassword', { token, apiUrl: env.ENV === 'dev' ? env.API_URL_DEV : env.API_URL_PROD })
})

export const newPasswordFromReset = asyncHandler(async (req, res) => {
    console.log(req.body.token, req.body.new_password)
    const {
        token,
        new_password,
        confirm_new_password
    } = req.body

    if (!token || token == '') {
        res.status(400)
        // throw new Error("TOKEN_REQUIRED")
        return res.render('failedResetPassword')
    }

    if(!new_password || new_password == ''){
        res.status(400)
        // throw new Error("NEW_PASSWORD_REQUIRED")
        return res.render('failedResetPassword')
    }

    if (!confirm_new_password || confirm_new_password == '') {
        res.status(400)
        // throw new Error("NEW_PASSWORD_REQUIRED")
        return res.render('failedResetPassword')
    }

    if (new_password !== confirm_new_password) {
        res.status(400)
        // throw new Error("PASSWORDS_NOT_MATCH")
        return res.render('failedResetPassword')
    }

    if (new_password.trim().length === 0 || new_password.includes(" ")) {
        res.status(400)
        // throw new Error("PASSWORD_CONTAIN_SPACE")
        return res.render('failedResetPassword')
    }

    const isTokenValid = await Token.findOne({token})

    if(!isTokenValid){
        res.status(400)
        // throw new Error("INVALID_TOKEN")
        return res.render('tokenExpired')
    }

    if(new Date(isTokenValid.expiryAt) < Date.now()){
        res.status(400)
        // throw new Error("EXPIRED")
        return res.render('tokenExpired')
    }

    const user = await User.findOne({
        email: isTokenValid.email
    })

    if (!user) {
        res.status(400)
        // throw new Error("INVALID_TOKEN")
        return res.render('tokenExpired')
    }

    // make salt
    let salt = await bcrypt.genSalt(12)
    // hash the password
    let hashedPassword = await bcrypt.hash(new_password, salt)

    // update db
    const updateDb = await User.updateOne({
        _id: user._id
    }, {
        $set: {
            password: hashedPassword
        }
    })

    if (!updateDb) {
        res.status(500)
        // throw new Error("PASSWORD_CHANGE_FAILED")
        return res.render('failedResetPassword')

    }

    const deleteTokenDb = await Token.findOneAndDelete({
        token
    })

    if (!deleteTokenDb) {
        console.log('delete token failed')
        // res.status(500)
        // throw new Error("DELETE_TOKEN_FAILED")
    }

    res.render('passwordSuccess')
})