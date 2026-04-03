const mongoose = require('mongoose');

const keySchema = new mongoose.Schema({
    key: {
        type: String,
        required: true,
        unique: true,
        uppercase: true,
        index: true
    },
    type: {
        type: String,
        enum: ['free', 'premium', 'lifetime'],
        default: 'free'
    },
    expiry: {
        type: Number,
        required: true
    },
    duration: {
        type: Number,
        default: 24 // hours
    },
    hwid: {
        type: String,
        default: null
    },
    hwidDiscord: {
        type: String,
        default: null
    },
    revoked: {
        type: Boolean,
        default: false
    },
    createdBy: {
        type: String,
        default: 'admin'
    },
    boundAt: {
        type: Date,
        default: null
    },
    boundAtDiscord: {
        type: Date,
        default: null
    },
    lastUsed: {
        type: Date,
        default: null
    }
}, {
    timestamps: true
});

keySchema.index({ expiry: 1 });
keySchema.index({ hwid: 1 });
keySchema.index({ hwidDiscord: 1 });
keySchema.index({ revoked: 1 });

module.exports = mongoose.model('Key', keySchema);
