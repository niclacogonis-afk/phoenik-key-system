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
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://niclacogonis_db_user:Pia201207mongosh@phoenikkeysystem.scfeitw.mongodb.net/phoenikkeys?retryWrites=true&w=majority';
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
        const { key, hwid } = req.body;

        if (!key || !hwid) {
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

        // HWID binding
        if (!license.hwid) {
            license.hwid = hwid;
            license.boundAt = new Date();
            await license.save();
            return res.json({ status: 'valid', message: 'Key activated', type: license.type });
        }

        if (license.hwid !== hwid) {
            return res.json({ status: 'hwid_mismatch', message: 'Key is bound to another PC' });
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
    res.redirect('https://link-to-your-linkvertise-or-lootlabs.com');
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
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Phoenik Key System running on port ${PORT}`);
    console.log(`Admin panel: http://localhost:${PORT}/admin.html`);

    // Connect to MongoDB after server starts
    mongoose.connect(MONGO_URI)
        .then(() => console.log('MongoDB connected'))
        .catch(err => {
            console.error('MongoDB connection error:', err.message);
            console.log('Server running without DB. Retrying connection...');
            // Retry connection every 10 seconds
            const retryInterval = setInterval(() => {
                mongoose.connect(MONGO_URI)
                    .then(() => {
                        console.log('MongoDB connected on retry');
                        clearInterval(retryInterval);
                    })
                    .catch(e => console.error('MongoDB retry failed:', e.message));
            }, 10000);
        });
});
