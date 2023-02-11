import express from "express";
import morgan from 'morgan'
import mongoose from "mongoose";
import cors from "cors";
import cookieParser from "cookie-parser"
import fileUpload from 'express-fileupload'
import path from 'path'
import {fileURLToPath} from 'url';
import dotenv from 'dotenv';

const env = dotenv.config().parsed;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// IMPORT MIDDLEWARES
import errorHandler from "./src/middlewares/errorMiddleware.js";

// IMPORT ROUTES
import authRouter from "./src/routes/authRouter.js";

// IMPORT FUNCTIONS
import dbConnection from "./src/libraries/dbConnect.js";

dbConnection();

const app = express();

// EJS
app.set('views', path.join(__dirname, '/src', 'views'));
app.set('view engine', 'ejs')

// MIDDLEWARES
if(process.env.ENV === 'dev'){
    app.use(cors({credentials: true, origin: `${process.env.CLIENT_URL_DEV}`}));
} else if (process.env.ENV === 'prod') {
    app.use(cors({credentials: true, origin: `${process.env.CLIENT_URL_PROD}`}));
}
// app.use(express.urlencoded({
//     extended: true
// }));
app.use(cookieParser());
app.use(express.json());
app.use(morgan('dev'));
app.use(fileUpload());

// ROUTES
app.use('/api/auth', authRouter)

// ERROR HANDLER
app.use(errorHandler)

// APP LISTEN
const port = env.PORT || 8000
app.listen(port, () => console.log('App listen on port ' + port))