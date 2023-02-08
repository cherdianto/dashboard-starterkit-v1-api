import mongoose from "mongoose"

const Schema = new mongoose.Schema({
    nama: {
        type: String,
        trim: true,
        required: true,
    },
    nim: {
        type: Number,
        trim: true,
        required: true,
    },
    whatsapp: {
        type: String,
        trim: true,
        unique: true,
    },
    alamat: {
        type: String,
        trim: true,
    },
    email: {
        type: String,
        trim: true,
        required: true,
        unique: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true
    },
    salt: String,
    sig: {
        type: String,
        enum: ['Ya', 'Tidak'],
        default: 'Tidak'
    },
    reg: {
        type: String,
        enum: ['Ya', 'Tidak'],
        default: 'Tidak'
    },
    adminSig: {
        type: String,
        enum: ['Ya', 'Tidak'],
        default: 'Tidak'
    },
    adminReg: {
        type: String,
        enum: ['Ya', 'Tidak'],
        default: 'Tidak'
    },
    adminSurat: {
        type: String,
        enum: ['Ya', 'Tidak'],
        default: 'Tidak'
    },
    role: {
        type: String,
        enum: ['Superadmin', 'Admin', 'Pimpinan', 'Regular'],
        default: 'Regular'
    },
    delegasi: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    refreshToken: {
        type: String
    }, 
    accessToken: {
        type: String
    }, 
    // accountType: {
    //     type: String,
    //     default: 'regular'
    // },
    status: {
        type: String,
        enum: ['Aktif', 'Non-aktif', 'Blokir'],
        default: 'Aktif'
    },
    jurusan: {
        type: String
    },
    tempatLahir: String,
    tanggalLahir: Date,
    scopeAdminSurat: [String]
}, {
    timestamps: {currentTime: () => Math.floor(Date.now() / 1000)}
})

export default mongoose.model('User', Schema)