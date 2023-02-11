import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import User from '../models/User.js'
import asyncHandler from 'express-async-handler'
const env = dotenv.config().parsed

// check token that being sent by cookies during request,
// output success : continue to the next request with additional parameter
// -- req.user = user data without password
// output error :
// -- no token : TOKEN_REQUIRED 401
// -- invalid token : INVALID_TOKEN 401
// -- no valid user : NO_USER_FOUND
const verifyToken = asyncHandler(async (req, res, next) => {
    let userId = ''

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    console.log(token)
    if (!token) {
        res.status(401)
        throw new Error('TOKEN_REQUIRED')
    }

    jwt.verify(token, env.ACCESS_TOKEN_SECRET, (error, decoded) => {
        if (error) {
            console.log(error)
            // errors = invalid signature, jwt malformed, jwt must be provided, invalid token, jwt expired
            res.status(401)
            throw new Error("INVALID_TOKEN")
        } else {
            userId = decoded.id
        }
    })

    const user = await User.findById(userId)

    if (!user) {
        res.status(400)
        throw new Error('NO_USER_FOUND')
    }
    
    req.user = user

    next()
})

export default verifyToken