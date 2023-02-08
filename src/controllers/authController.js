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
    const updateDb = await User.updateOne({
        _id: user._id
    }, {
        $set: {
            refreshToken,
            accessToken
        }
    })

    if (!updateDb) {
        res.status(500)
        throw new Error("ERROR_UPDATE_DB")
    }

    // if updateDB success, then set cookies 
    if(env.ENV === 'dev'){
        res.cookie('refreshToken', refreshToken, {
            maxAge: 7 * 24 * 60 * 60 * 1000,
            httpOnly: true
        })
    } else {
        res.cookie('refreshToken', refreshToken, {
            maxAge: 7 * 24 * 60 * 60 * 1000,
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            domain: 'cherdianto.site',
            path: '/'
        })
    }

    // res.cookie('accessToken', accessToken, {
    //     maxAge: 1 * 60 * 60 * 1000,
    //     httpOnly: true,
    //     secure: true,
    //     sameSite: 'strict',
    //     domain: 'cherdianto.site',
    //     path: '/'
    // })
    // return
    res.status(200).json({
        status: true,
        message: "LOGIN_SUCCESS",
        fullname: user.fullname,
        whatsapp: user.whatsapp,
        email: user.email,
        language: user.language,
        // accessToken,
        // refreshToken
    })
})

export const updateProfile = asyncHandler(async (req, res) => {
    const {
        fullname,
        email,
        whatsapp,
        language
    } = req.body

    const userId = req.user._id

    // check the req.body
    if (!fullname) {
        res.status(400)
        throw new Error('FULLNAME_REQUIRED')
    }

    if (!email) {
        res.status(400)
        throw new Error('EMAIL_REQUIRED')
    }

    if (!whatsapp) {
        res.status(400)
        throw new Error('WHATSAPP_REQUIRED')
    }

    if (!language) {
        res.status(400)
        throw new Error('LANGUAGE_REQUIRED')
    }

    // const userExist = await User.findOne({
    //     email: email
    // })

    // if (userExist) {
    //     res.status(400)
    //     throw new Error('DUPLICATE_EMAIL')
    // }
    if( whatsapp != req.user.whatsapp ){
        const whatsappExist = await User.findOne({
            whatsapp
        })
    
        if (whatsappExist) {
            res.status(400)
            throw new Error('DUPLICATE_WHATSAPP')
        }
    }

    // // make salt
    // let salt = await bcrypt.genSalt(12)
    // // hash the password
    // let hashedPassword = await bcrypt.hash(password, salt)

    // store user info to DB
    try {
        const user = await User.findByIdAndUpdate( userId, {
            $set: {
                fullname,
                whatsapp,
                language,
                email
            }
        }, { new: true })

        res.status(200).json({
            status: true,
            message: 'PROFILE_UPDATE_SUCCESS',
            user : {
                fullname,
                whatsapp,
                language,
                email
            }
        })

    } catch (error) {
        res.status(500)
        // console.log(error)
        throw new Error('USER_REGISTER_FAILED')
    }
})

export const logout = asyncHandler(async (req, res) => {
    const userRefreshToken = req.cookies.refreshToken
    console.log(req.cookies)

    if (!userRefreshToken) {
        res.status(204)
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            domain: 'cherdianto.site',
            path: '/'
        })
        // throw new Error("NO_REFRESH_TOKEN")
        return res.status(200).json({
            status: true,
            message: "LOGGED_OUT_SUCCESS_WTH_RFSTKN"
        })
    }

    // const user = await User.findOne({
    //     refreshToken: userRefreshToken
    // })

    // if (!user) {
    //     res.status(204)
    //     throw new Error("USER_NOT_FOUND")
    // }

    jwt.verify(userRefreshToken, refreshSecretKey, async (error, decoded) => {
        
        if(env.ENV === 'dev'){
            res.clearCookie('refreshToken')
        } else {
            res.clearCookie('refreshToken', {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                domain: 'cherdianto.site',
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

export const changePassword = asyncHandler(async (req, res) => {
    // form : email, oldpassword, newpassword

    const {
        email,
        oldPassword,
        newPassword
    } = req.body

    const user = req.user

    // console.log(email)
    // console.log(user)

    if (!email || email == '') {
        res.status(400)
        throw new Error("EMAIL_REQUIRED")
    }

    // if(!oldPassword || oldPassword == ''){
    //     res.status(400)
    //     throw new Error("OLD_PASSWORD_REQUIRED")
    // }

    if (!newPassword || newPassword == '') {
        res.status(400)
        throw new Error("NEW_PASSWORD_REQUIRED")
    }

    if (newPassword.trim().length === 0 || newPassword.includes(" ")) {
        res.status(400)
        throw new Error("PASSWORD_CONTAIN_SPACE")
    }

    if (email !== user.email) {
        res.status(400)
        throw new Error("EMAIL_NOT_FOUND")
    }

    const oldUserData = await User.findOne({
        email
    })
    if (!oldUserData) {
        res.status(400)
        throw new Error("USER_NOT_FOUND")
    }

    const isMatch = bcrypt.compareSync(oldPassword, oldUserData.password)
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

export const refreshToken = asyncHandler(async (req, res) => {
    const userRefreshToken = req.cookies.refreshToken
    // console.log('masuk refresh token')
    // console.log(userRefreshToken)

    if (!userRefreshToken) {
        res.status(401)
        throw new Error("REFRESH_TOKEN_NOT_FOUND")
    }

    // const user = await User.findOne({
    //     refreshToken: userRefreshToken
    // })

    // if (!user) {
    //     res.status(401)
    //     throw new Error("USER_NOT_LOGGED_IN")
    // }

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

export const getUser = asyncHandler(async (req, res) => {

    const user = await User.findById(req.user._id).select('-password -accessToken -refreshToken')
    // console.log(user)
    res.status(200).json({
        status: true,
        message: "GET_USER_SUCCESS",
        user
    })
})

export const resetPassword = asyncHandler(async (req, res) => {
    // form : email, oldpassword, newpassword
    // console.log(req.query.email)

    const email = req.query.email

    // const user = req.user

    // console.log(email)
    // console.log(user)

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
    // expiryAt.setHours(expiryAt.getHours() + 24)
    expiryAt.setMinutes(expiryAt.getMinutes() + 2)

    const newToken = await Token.create({
        email,
        token: generateToken(),
        expiryAt
    })

    // console.log(newToken)
    if(!newToken){
        res.status(400)
        throw new Error("RESET_LINK_FAILED")
    }

    res.status(200).json({
        status: true,
        message: "RESET_LINK_SUCCESS",
        token: newToken
    })
})

export const validateResetLink = asyncHandler(async (req, res) => {
    const token = req.query.token

    const isValid = await Token.findOne({token})

    if(!isValid){
        res.status(400)
        throw new Error("INVALID_TOKEN")
    }

    if(new Date(isValid.expiryAt) < Date.now()){
        res.status(400)
        throw new Error("EXPIRED")
    }

    res.status(200).json("LINK ACTIVE, PROVIDE A FORM(OLD PWD, NEW PWD) TO USER VIA EJS")
    // res.render('resetPassword')
    // res.status(200).json({
    //     status: true,
    //     message: "LINK_VALID",
    //     isValid
    // })
})