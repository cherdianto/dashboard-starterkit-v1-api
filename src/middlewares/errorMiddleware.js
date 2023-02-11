import dotenv from 'dotenv'
const env = dotenv.config().parsed

const errorHandler = (err, req, res, next) => {
    // console.log(res.statusCode)
    // console.log(req)
    // console.log(res)

    const statusCode = res.statusCode ? res.statusCode : 500

    const errorDetail = {
        status: false,
        message: err.message,
        stack: env.ENV === 'dev' ? err.stack : null
    }

    console.log(errorDetail)
    res.status(statusCode).json(errorDetail)
}

export default errorHandler