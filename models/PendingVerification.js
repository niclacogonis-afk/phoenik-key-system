const mongoose = require('mongoose');

const pendingVerificationSchema = new mongoose.Schema({
    hwid: {
        type: String,
        required: true,
        index: true
    },
    token: {
        type: String,
        required: true,
        unique: true
    },
    type: {
        type: String,
        enum: ['linkvertise', 'lootlabs'],
        required: true
    },
    ytCompleted: {
        type: Boolean,
        default: false
    },
    cpCompleted: {
        type: Boolean,
        default: false
    },
    cpCompletedAt: {
        type: Date,
        default: null
    },
    keyIssued: {
        type: Boolean,
        default: false
    },
    issuedKey: {
        type: String,
        default: null
    },
    ytStartedAt: {
        type: Date,
        default: Date.now
    },
    ip: {
        type: String,
        default: null
    },
    expiresAt: {
        type: Date,
        default: () => new Date(Date.now() + 60 * 60 * 1000) // 1 hour
    }
}, {
    timestamps: true
});

pendingVerificationSchema.index({ hwid: 1 });
pendingVerificationSchema.index({ token: 1 });
pendingVerificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('PendingVerification', pendingVerificationSchema);
