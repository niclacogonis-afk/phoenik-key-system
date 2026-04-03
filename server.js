const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();

// === CONFIG ===
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://niclacogonis_db_user:Phoenik2024@phoenikkeysystem.scfeitw.mongodb.net/phoenikkeys?retryWrites=true&w=majority&appName=PhoenikKeysystem';
const JWT_SECRET = process.env.JWT_SECRET || 'ANG20p1207n!';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'N201207p';

// === MIDDLEWARE ===
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests, try again later.' }
});
app.use('/api/', apiLimiter);

const validateLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 10,
    message: { error: 'Rate limited. Wait a minute.' }
});

// === MODELS ===
const Key = require('./models/Key');
const User = require('./models/User');
const PendingVerification = require('./models/PendingVerification');

// === AUTH MIDDLEWARE ===
function authMiddleware(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.admin = decoded;
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// === API ROUTES ===

// Validate key (called by C# client)
app.post('/api/validate', validateLimiter, async (req, res) => {
    try {
        const { key, hwid, hwidDiscord } = req.body;

        if (!key || (!hwid && !hwidDiscord)) {
            return res.json({ status: 'invalid', message: 'Missing key or HWID' });
        }

        const license = await Key.findOne({ key: key.trim().toUpperCase() });

        if (!license) {
            return res.json({ status: 'invalid', message: 'Key does not exist' });
        }

        if (license.revoked) {
            return res.json({ status: 'invalid', message: 'Key has been revoked' });
        }

        if (Date.now() > license.expiry) {
            return res.json({ status: 'expired', message: 'Key has expired' });
        }

        // Handle executor HWID binding
        if (hwid) {
            if (!license.hwid) {
                license.hwid = hwid;
                license.boundAt = new Date();
                await license.save();
                return res.json({ status: 'valid', message: 'Key activated', type: license.type });
            }

            if (license.hwid !== hwid) {
                return res.json({ status: 'hwid_mismatch', message: 'Key is bound to another PC' });
            }
        }

        // Handle Discord HWID binding
        if (hwidDiscord) {
            if (!license.hwidDiscord) {
                license.hwidDiscord = hwidDiscord;
                license.boundAtDiscord = new Date();
                await license.save();
                return res.json({ status: 'valid', message: 'Discord key activated', type: license.type });
            }

            if (license.hwidDiscord !== hwidDiscord) {
                return res.json({ status: 'hwid_mismatch', message: 'Key is bound to another Discord account' });
            }
        }

        // Key is valid if at least one HWID is set and matches
        if (!license.hwid && !license.hwidDiscord) {
            return res.json({ status: 'invalid', message: 'Key not bound to any device' });
        }

        // Update last used
        license.lastUsed = new Date();
        await license.save();

        const timeLeft = license.expiry - Date.now();
        const hoursLeft = Math.floor(timeLeft / (1000 * 60 * 60));
        const minutesLeft = Math.floor((timeLeft % (1000 * 60 * 60)) / (1000 * 60));

        return res.json({
            status: 'valid',
            message: `Valid! ${hoursLeft}h ${minutesLeft}m remaining`,
            type: license.type,
            expiresAt: new Date(license.expiry).toISOString()
        });

    } catch (err) {
        console.error('Validate error:', err);
        return res.status(500).json({ status: 'error', message: 'Server error' });
    }
});

// Admin login
app.post('/api/admin/login', async (req, res) => {
    try {
        const { password } = req.body;

        if (password !== ADMIN_PASSWORD) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '24h' });
        return res.json({ token, message: 'Login successful' });
    } catch (err) {
        return res.status(500).json({ error: 'Server error' });
    }
});

// Generate key (admin only)
app.post('/api/admin/generate', authMiddleware, async (req, res) => {
    try {
        const { type = 'free', duration = 24, count = 1, prefix = 'PHOENIK' } = req.body;

        const keys = [];
        for (let i = 0; i < Math.min(count, 50); i++) {
            const keyValue = generateKey(prefix);
            const expiry = Date.now() + (duration * 60 * 60 * 1000);

            const key = new Key({
                key: keyValue,
                type,
                expiry,
                duration,
                createdBy: 'admin'
            });
            await key.save();
            keys.push({ key: keyValue, type, duration: `${duration}h`, expiresAt: new Date(expiry).toISOString() });
        }

        return res.json({ keys, message: `Generated ${keys.length} key(s)` });
    } catch (err) {
        console.error('Generate error:', err);
        return res.status(500).json({ error: 'Server error' });
    }
});

// Get all keys (admin only)
app.get('/api/admin/keys', authMiddleware, async (req, res) => {
    try {
        const { page = 1, limit = 50, status = 'all' } = req.query;
        let filter = {};

        if (status === 'active') filter = { expiry: { $gt: Date.now() }, revoked: false };
        else if (status === 'expired') filter = { expiry: { $lte: Date.now() } };
        else if (status === 'revoked') filter = { revoked: true };
        else if (status === 'bound') filter = { hwid: { $ne: null } };

        const keys = await Key.find(filter)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(parseInt(limit));

        const total = await Key.countDocuments(filter);

        return res.json({ keys, total, page: parseInt(page), pages: Math.ceil(total / limit) });
    } catch (err) {
        return res.status(500).json({ error: 'Server error' });
    }
});

// Revoke key (admin only)
app.post('/api/admin/revoke', authMiddleware, async (req, res) => {
    try {
        const { key } = req.body;
        const result = await Key.findOneAndUpdate(
            { key: key.trim().toUpperCase() },
            { revoked: true },
            { new: true }
        );

        if (!result) return res.status(404).json({ error: 'Key not found' });
        return res.json({ message: 'Key revoked', key: result.key });
    } catch (err) {
        return res.status(500).json({ error: 'Server error' });
    }
});

// Unbind HWID (admin only)
app.post('/api/admin/unbind', authMiddleware, async (req, res) => {
    try {
        const { key } = req.body;
        const result = await Key.findOneAndUpdate(
            { key: key.trim().toUpperCase() },
            { hwid: null, boundAt: null },
            { new: true }
        );

        if (!result) return res.status(404).json({ error: 'Key not found' });
        return res.json({ message: 'HWID unbound', key: result.key });
    } catch (err) {
        return res.status(500).json({ error: 'Server error' });
    }
});

// Delete key (admin only)
app.delete('/api/admin/keys/:key', authMiddleware, async (req, res) => {
    try {
        const result = await Key.findOneAndDelete({ key: req.params.key.toUpperCase() });
        if (!result) return res.status(404).json({ error: 'Key not found' });
        return res.json({ message: 'Key deleted' });
    } catch (err) {
        return res.status(500).json({ error: 'Server error' });
    }
});

// Extend key (admin only)
app.post('/api/admin/extend', authMiddleware, async (req, res) => {
    try {
        const { key, hours } = req.body;
        const license = await Key.findOne({ key: key.trim().toUpperCase() });
        if (!license) return res.status(404).json({ error: 'Key not found' });

        const extension = (hours || 24) * 60 * 60 * 1000;
        license.expiry = Math.max(license.expiry, Date.now()) + extension;
        license.duration += (hours || 24);
        await license.save();

        return res.json({ message: `Extended by ${hours || 24}h`, expiresAt: new Date(license.expiry).toISOString() });
    } catch (err) {
        return res.status(500).json({ error: 'Server error' });
    }
});

// Stats (admin only)
app.get('/api/admin/stats', authMiddleware, async (req, res) => {
    try {
        const total = await Key.countDocuments();
        const active = await Key.countDocuments({ expiry: { $gt: Date.now() }, revoked: false });
        const expired = await Key.countDocuments({ expiry: { $lte: Date.now() } });
        const revoked = await Key.countDocuments({ revoked: true });
        const bound = await Key.countDocuments({ hwid: { $ne: null } });
        const free = await Key.countDocuments({ type: 'free' });
        const premium = await Key.countDocuments({ type: 'premium' });

        return res.json({ total, active, expired, revoked, bound, free, premium });
    } catch (err) {
        return res.status(500).json({ error: 'Server error' });
    }
});

// Get Key redirect (for the "Get Key" button)
app.get('/getkey', (req, res) => {
    res.redirect('/getkey.html');
});

// === VERIFICATION ROUTES ===

// Check verification status
app.get('/api/verification/status', async (req, res) => {
    try {
        const { hwid } = req.query;
        if (!hwid) return res.json({ ytCompleted: false, cpCompleted: false, hasKey: false });

        const verification = await PendingVerification.findOne({ hwid });
        if (!verification) return res.json({ ytCompleted: false, cpCompleted: false, hasKey: false });

        return res.json({
            ytCompleted: verification.ytCompleted,
            cpCompleted: verification.cpCompleted,
            hasKey: verification.keyIssued,
            key: verification.issuedKey
        });
    } catch (err) {
        return res.json({ ytCompleted: false, cpCompleted: false, hasKey: false });
    }
});

// Initialize verification (called on page load - starts the timer)
app.post('/api/verification/init', async (req, res) => {
    try {
        const { hwid } = req.body;
        if (!hwid) return res.json({ success: false });

        let verification = await PendingVerification.findOne({ hwid });

        if (!verification) {
            verification = new PendingVerification({
                hwid,
                token: generateKey('TKN'),
                type: 'linkvertise',
                ip: req.ip,
                ytStartedAt: new Date()
            });
            await verification.save();
        }

        return res.json({ success: true });
    } catch (err) {
        return res.json({ success: false });
    }
});

// Start checkpoint verification
app.post('/api/verification/start-checkpoint', async (req, res) => {
    try {
        const { hwid, token, type } = req.body;
        if (!hwid || !token || !type) return res.status(400).json({ error: 'Missing data' });

        let verification = await PendingVerification.findOne({ hwid });

        if (!verification) {
            verification = new PendingVerification({
                hwid,
                token,
                type,
                ip: req.ip
            });
        } else {
            verification.token = token;
            verification.type = type;
            verification.ip = req.ip;
            verification.cpCompleted = false;
        }

        await verification.save();
        return res.json({ success: true, token });
    } catch (err) {
        return res.status(500).json({ error: 'Server error' });
    }
});

// Callback from Linkvertise/LootLabs
app.get('/api/verification/callback', async (req, res) => {
    try {
        const { token, hwid, type } = req.query;
        if (!token || !hwid) return res.status(400).send('Invalid callback');

        const verification = await PendingVerification.findOne({ hwid, token });
        if (!verification) return res.status(404).send('Verification not found');

        // Mark checkpoint as completed
        verification.cpCompleted = true;
        verification.cpCompletedAt = new Date();
        await verification.save();

        // Redirect back to getkey page
        res.redirect('/getkey.html?verified=checkpoint');
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// Verify YouTube (with anti-abuse)
app.post('/api/verification/verify-youtube', async (req, res) => {
    try {
        const { hwid } = req.body;
        if (!hwid) return res.json({ success: false, message: 'Missing HWID' });

        let verification = await PendingVerification.findOne({ hwid });

        if (!verification) {
            return res.json({ success: false, message: 'Please reload the page and try again' });
        }

        if (verification.ytCompleted) {
            return res.json({ success: true });
        }

        // Anti-abuse: require at least 8 seconds since page load
        const timeSinceStart = Date.now() - verification.ytStartedAt.getTime();
        if (timeSinceStart < 8000) {
            return res.json({
                success: false,
                message: `Please wait ${Math.ceil((8000 - timeSinceStart) / 1000)} more seconds`
            });
        }

        // Anti-abuse: check if same HWID already got a key today
        const existingKey = await Key.findOne({
            hwid: hwid,
            createdAt: { $gt: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        });
        if (existingKey) {
            return res.json({
                success: false,
                message: 'You already have an active key. Wait for it to expire.'
            });
        }

        verification.ytCompleted = true;
        await verification.save();

        return res.json({ success: true });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Verify checkpoint (manual verification with anti-abuse)
app.post('/api/verification/verify-checkpoint', async (req, res) => {
    try {
        const { hwid } = req.body;
        if (!hwid) return res.json({ success: false, message: 'Missing HWID' });

        const verification = await PendingVerification.findOne({ hwid });
        if (!verification) return res.json({ success: false, message: 'Please reload the page and try again' });

        if (verification.cpCompleted) return res.json({ success: true });

        // Anti-abuse: require at least 12 seconds since YouTube verification
        if (!verification.ytCompleted) {
            return res.json({ success: false, message: 'Complete YouTube step first' });
        }

        const timeSinceYt = Date.now() - verification.updatedAt.getTime();
        if (timeSinceYt < 12000) {
            return res.json({
                success: false,
                message: `Please wait ${Math.ceil((12000 - timeSinceYt) / 1000)} more seconds`
            });
        }

        verification.cpCompleted = true;
        verification.cpCompletedAt = new Date();
        await verification.save();

        return res.json({ success: true });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Claim key after all verifications
app.post('/api/verification/claim-key', async (req, res) => {
    try {
        const { hwid } = req.body;
        if (!hwid) return res.json({ success: false, message: 'Missing HWID' });

        const verification = await PendingVerification.findOne({ hwid });
        if (!verification) return res.json({ success: false, message: 'No verification found' });

        if (!verification.ytCompleted) return res.json({ success: false, message: 'YouTube not verified' });
        if (!verification.cpCompleted) return res.json({ success: false, message: 'Checkpoint not completed' });

        // Anti-abuse: check if same HWID already has an active key
        const existingKey = await Key.findOne({
            hwid: hwid,
            expiry: { $gt: Date.now() },
            revoked: false
        });
        if (existingKey) {
            verification.keyIssued = true;
            verification.issuedKey = existingKey.key;
            await verification.save();
            return res.json({ success: true, key: existingKey.key, message: 'You already have an active key' });
        }

        // Generate key
        const keyValue = generateKey('PHOENIK');
        const expiry = Date.now() + (24 * 60 * 60 * 1000); // 24 hours

        const key = new Key({
            key: keyValue,
            type: 'free',
            expiry,
            duration: 24,
            hwid,
            createdBy: 'getkey-page',
            boundAt: new Date()
        });
        await key.save();

        verification.keyIssued = true;
        verification.issuedKey = keyValue;
        await verification.save();

        return res.json({ success: true, key: keyValue });
    } catch (err) {
        return res.status(500).json({ success: false, message: 'Server error' });
    }
});

// === HELPER ===
function generateKey(prefix = 'PHOENIK') {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const segment = () => {
        let s = '';
        for (let i = 0; i < 4; i++) s += chars[Math.floor(Math.random() * chars.length)];
        return s;
    };
    return `${prefix}-${segment()}-${segment()}-${segment()}`;
}

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', mongo: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' });
});

app.get('/', (req, res) => {
    res.json({ name: 'Phoenik Key System', version: '1.0.0' });
});

// === CONNECT DB & START ===
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err.message);
});

process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err?.message || err);
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Phoenik Key System running on port ${PORT}`);
    console.log(`Admin panel: http://localhost:${PORT}/admin.html`);

    // Connect to MongoDB after server starts
    mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 })
        .then(() => console.log('MongoDB connected'))
        .catch(err => {
            console.error('MongoDB connection error:', err.message);
            console.log('Server running without DB. Retrying connection...');
            // Retry connection every 15 seconds
            const retryInterval = setInterval(() => {
                mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 })
                    .then(() => {
                        console.log('MongoDB connected on retry');
                        clearInterval(retryInterval);
                    })
                    .catch(e => console.error('MongoDB retry failed:', e.message));
            }, 15000);
        });
});
