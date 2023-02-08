import mongoose from "mongoose"
import dotenv from 'dotenv'
const env = dotenv.config().parsed
const dbUrl = env.ENV === 'dev' ? env.DATABASE_DEV : env.DATABASE_PROD

function dbConnection(){
        mongoose.connect(dbUrl, {
        useNewUrlParser: true,
        useUnifiedTopology: true
    })

    const db = mongoose.connection
    db.on('error', (error) => console.log(error))
    db.once('open', () => console.log('database connected'))
}

export default dbConnection