import http from 'http';
import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { Server as SocketIOServer } from 'socket.io';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import nodemailer from 'nodemailer';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();

// Enhanced CORS configuration for production
const allowedOrigins = [
  'https://xevytalk-client.onrender.com',
  'http://localhost:5173',
  'http://localhost:3000',
  'http://127.0.0.1:5173'
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    // In production, log and allow (for debugging)
    console.log('CORS request from origin:', origin);
    callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-user-id']
}));

// Handle OPTIONS requests explicitly
app.options('*', cors());

app.use(express.json());

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Serve uploaded files with proper headers
app.use('/uploads', express.static(uploadDir, {
  setHeaders: (res, path) => {
    res.set('Cross-Origin-Resource-Policy', 'cross-origin');
    res.set('Access-Control-Allow-Origin', '*');
  }
}));

// Configure Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({ storage: storage });

const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: allowedOrigins,
    methods: ['GET', 'POST'],
    credentials: true
  },
  transports: ['websocket', 'polling'],
  allowEIO3: true
});

const MONGO_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/chatbot';
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-prod';

// --- Message encryption helpers (server-side, at-rest encryption) ---
// NOTE: This is NOT end-to-end encryption. The server can decrypt messages.
const ENC_ALGO = 'aes-256-gcm';
const ENC_KEY = crypto
  .createHash('sha256')
  .update(process.env.MESSAGE_ENC_SECRET || JWT_SECRET || 'fallback-message-secret')
  .digest(); // 32 bytes

const encryptText = (plain = '') => {
  if (!plain) return '';
  const iv = crypto.randomBytes(12); // recommended size for GCM
  const cipher = crypto.createCipheriv(ENC_ALGO, ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Store as base64(iv):base64(tag):base64(cipherText)
  return `${iv.toString('base64')}:${tag.toString('base64')}:${enc.toString('base64')}`;
};

const decryptText = (packed = '') => {
  if (!packed) return '';
  try {
    const [ivB64, tagB64, dataB64] = String(packed).split(':');
    if (!ivB64 || !tagB64 || !dataB64) return '';
    const iv = Buffer.from(ivB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const data = Buffer.from(dataB64, 'base64');
    const decipher = crypto.createDecipheriv(ENC_ALGO, ENC_KEY, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(data), decipher.final()]);
    return dec.toString('utf8');
  } catch (e) {
    console.error('Failed to decrypt message content', e.message);
    return '';
  }
};

// Email configuration
const emailTransporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'admin@xevyte.com',
    pass: 'figjfdnpaaygcfrj' // App password
  }
});

// Function to send welcome email with credentials
const sendWelcomeEmail = async (email, username, password) => {
  const mailOptions = {
    from: '"XevyTalk Admin" <admin@xevyte.com>',
    to: email,
    subject: 'Welcome to XevyTalk - Your Account Credentials',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #0891b2 0%, #0e7490 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
          .credentials { background: white; padding: 20px; border-left: 4px solid #0891b2; margin: 20px 0; }
          .button { display: inline-block; background: #0891b2; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin-top: 20px; }
          .footer { text-align: center; margin-top: 20px; color: #666; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>💬 Welcome to XevyTalk!</h1>
          </div>
          <div class="content">
            <h2>Hello ${username},</h2>
            <p>Your account has been created successfully. You can now login to XevyTalk to chat with your teammates!</p>
            
            <div class="credentials">
              <h3>Your Login Credentials:</h3>
              <p><strong>Email:</strong> ${email}</p>
              <p><strong>Password:</strong> ${password}</p>
            </div>
            
            <p><strong>Important:</strong> Please change your password after your first login for security purposes.</p>
            
            <a href="http://localhost:5173/login" class="button">Login to XevyTalk</a>
            
            <div class="footer">
              <p>This is an automated email. Please do not reply.</p>
              <p>&copy; 2025 XevyTalk. All rights reserved.</p>
            </div>
          </div>
        </div>
      </body>
      </html>
    `
  };

  try {
    await emailTransporter.sendMail(mailOptions);
    console.log(`✓ Welcome email sent to ${email}`);
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    return false;
  }
};

// Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true }, // Display name
  email: { type: String, required: true, unique: true }, // Login email
  avatar: { type: String },
  lastSeenAt: { type: Date, default: Date.now },
  passwordHash: { type: String },
  phone: { type: String },
  address: { type: String },
  isAdmin: { type: Boolean, default: false }
}, { timestamps: true });

const conversationSchema = new mongoose.Schema({
  type: { type: String, enum: ['direct', 'group'], required: true },
  name: { type: String },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  lastMessageAt: { type: Date, default: Date.now },
  hiddenFor: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
}, { timestamps: true });

const messageSchema = new mongoose.Schema({
  conversation: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation', required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  // Plain text content kept optional for backward compatibility;
  // encrypted content is stored in contentEnc.
  content: { type: String },
  contentEnc: { type: String },
  deliveredTo: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  seenBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  tempId: { type: String },
  attachments: [{
    url: String,
    name: String,
    type: String,
    size: Number
  }],
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Conversation = mongoose.model('Conversation', conversationSchema);
const Message = mongoose.model('Message', messageSchema);

// Normalize message shape for API / socket responses.
// If encrypted content exists, decrypt it into .content field.
const toSafeMessage = (m) => {
  if (!m) return m;
  const obj = m.toObject ? m.toObject() : { ...m };
  if (obj.contentEnc) {
    const decrypted = decryptText(obj.contentEnc);
    if (decrypted) obj.content = decrypted;
  }
  return obj;
};

// Helpers
const signToken = (u) => jwt.sign({ uid: String(u._id) }, JWT_SECRET, { expiresIn: '7d' });
const getUserFromToken = async (authHeader) => {
  if (!authHeader) return null;
  const [type, token] = authHeader.split(' ');
  if (type !== 'Bearer' || !token) return null;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const u = await User.findById(payload.uid);
    return u || null;
  } catch {
    return null;
  }
};

const auth = async (req, res, next) => {
  // Prefer Bearer token, fallback to x-user-id for dev
  let u = await getUserFromToken(req.header('authorization'));
  if (!u) {
    const userId = req.header('x-user-id');
    if (userId) u = await User.findById(userId);
  }
  if (!u) return res.status(401).json({ error: 'unauthorized' });
  req.user = u;
  next();
};

// Routes
app.post('/api/auth/guest', async (req, res) => {
  const { username } = req.body || {};
  const name = username || `Guest ${String(Math.floor(Math.random() * 9000) + 1000)}`;
  const u = new User({ username: name, avatar: `https://api.dicebear.com/8.x/pixel-art/svg?seed=${encodeURIComponent(name)}` });
  await u.save();
  res.json(u);
});

// Auth: register, login, me
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body || {};

  // Validate required fields
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email and password are required' });
  }

  // Validate email domain
  if (!email.endsWith('@xevyte.com')) {
    return res.status(400).json({ error: 'Email must be from @xevyte.com domain' });
  }

  // Check if email already exists
  const exists = await User.findOne({ email });
  if (exists) {
    return res.status(409).json({ error: 'Email already registered' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const u = new User({
    username: name,
    email,
    passwordHash,
    avatar: `https://api.dicebear.com/8.x/pixel-art/svg?seed=${encodeURIComponent(name)}`,
    isAdmin: email === 'admin@xevyte.com'
  });
  await u.save();
  res.json({ token: signToken(u), user: u });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const u = await User.findOne({ email });
  if (!u || !u.passwordHash) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const ok = await bcrypt.compare(password, u.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  res.json({ token: signToken(u), user: u });
});

app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  // Always use HTTPS for production URLs
  const protocol = process.env.NODE_ENV === 'production' ? 'https' : req.protocol;
  const host = req.get('host');
  const fileUrl = `${protocol}://${host}/uploads/${req.file.filename}`;

  res.json({
    url: fileUrl,
    name: req.file.originalname,
    type: req.file.mimetype,
    size: req.file.size
  });
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json(req.user);
});

app.get('/api/users', async (req, res) => {
  const users = await User.find().sort({ createdAt: -1 }).limit(50);
  res.json(users);
});

// Update my profile
app.put('/api/users/me', auth, async (req, res) => {
  try {
    const allowed = ['email', 'phone', 'address', 'avatar', 'username']
    const patch = {}
    for (const k of allowed) if (k in req.body) patch[k] = req.body[k]

    const updated = await User.findByIdAndUpdate(
      req.user._id,
      { $set: patch },
      { new: true, runValidators: true }
    )

    if (!updated) {
      return res.status(404).json({ error: 'User not found' })
    }

    // Return the updated user without sensitive data
    const { passwordHash, ...userWithoutPassword } = updated.toObject()
    res.json(userWithoutPassword)
  } catch (error) {
    console.error('Error updating user:', error)
    res.status(400).json({ error: error.message || 'Failed to update profile' })
  }
});

// Admin-only: Create user
app.post('/api/admin/create-user', auth, async (req, res) => {
  try {
    // Check if user is admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Unauthorized. Admin access required.' });
    }

    const { username, email } = req.body;

    // Validate required fields
    if (!username || !email) {
      return res.status(400).json({ error: 'Username and email are required' });
    }

    // Validate email domain
    if (!email.endsWith('@xevyte.com')) {
      return res.status(400).json({ error: 'Email must be from @xevyte.com domain' });
    }

    // Check if email already exists
    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    // Generate a random secure password
    const randomPassword = crypto.randomBytes(8).toString('hex'); // 16 character hex string
    const passwordHash = await bcrypt.hash(randomPassword, 10);

    const newUser = new User({
      username,
      email,
      passwordHash,
      avatar: `https://api.dicebear.com/8.x/pixel-art/svg?seed=${encodeURIComponent(username)}`,
      isAdmin: false
    });

    await newUser.save();

    // Send welcome email with credentials
    const emailSent = await sendWelcomeEmail(email, username, randomPassword);

    // Return user without password
    const { passwordHash: _, ...userWithoutPassword } = newUser.toObject();
    res.json({
      user: userWithoutPassword,
      password: randomPassword,
      emailSent,
      message: emailSent
        ? `User created successfully. Credentials sent to ${email}`
        : 'User created but email failed to send. Please share credentials manually.'
    });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: error.message || 'Failed to create user' });
  }
});

app.get('/api/conversations', auth, async (req, res) => {
  let list = await Conversation.find({
    members: req.user._id,
    hiddenFor: { $ne: req.user._id }
  })
    .sort({ updatedAt: -1 })
    .populate('members')
    .limit(50);

  const listWithUnread = await Promise.all(list.map(async (conv) => {
    const unreadCount = await Message.countDocuments({
      conversation: conv._id,
      sender: { $ne: req.user._id },
      seenBy: { $ne: req.user._id }
    });
    return { ...conv.toObject(), unreadCount };
  }));

  const final = listWithUnread.filter(c => !(c.type === 'group' && (String(c.name || '').trim().toLowerCase() === 'lobby')));
  res.json(final);
});

app.get('/api/conversations/:id', auth, async (req, res) => {
  try {
    const conv = await Conversation.findById(req.params.id).populate('members');
    if (!conv) {
      return res.status(404).json({ error: 'Conversation not found' });
    }
    // Check if user is a member
    if (!conv.members.some(m => String(m._id) === String(req.user._id))) {
      return res.status(403).json({ error: 'Access denied' });
    }
    res.json(conv);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});


app.post('/api/conversations/direct', auth, async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });
  let conv = await Conversation.findOne({ type: 'direct', members: { $all: [req.user._id, userId], $size: 2 } });
  let isNew = false;
  if (!conv) {
    conv = new Conversation({ type: 'direct', members: [req.user._id, userId] });
    await conv.save();
    isNew = true;
  } else {
    // If conversation exists but is hidden for current user, unhide it
    if (conv.hiddenFor && conv.hiddenFor.includes(req.user._id)) {
      conv.hiddenFor = conv.hiddenFor.filter(id => String(id) !== String(req.user._id));
      await conv.save();
      // Treat as new for the user since it's reappearing
      // But we don't need to notify the other user if they already see it
    }
  }
  const populated = await Conversation.findById(conv._id).populate('members');

  // Notify OTHER members about the new conversation (not the creator)
  if (isNew) {
    populated.members.forEach(member => {
      // Don't emit to the creator (req.user._id)
      if (String(member._id) !== String(req.user._id)) {
        io.to(`user:${member._id}`).emit('conversation_created', populated);
      }
    });
  }

  res.json(populated);
});

app.post('/api/conversations/group', auth, async (req, res) => {
  const { name, memberIds } = req.body;
  if (!name || !Array.isArray(memberIds) || memberIds.length < 2) {
    return res.status(400).json({ error: 'name and at least 2 members required' });
  }
  const conv = new Conversation({ type: 'group', name, members: [req.user._id, ...memberIds] });
  await conv.save();
  const populated = await Conversation.findById(conv._id).populate('members');

  // Notify OTHER members about the new group (not the creator)
  populated.members.forEach(member => {
    // Don't emit to the creator (req.user._id)
    if (String(member._id) !== String(req.user._id)) {
      io.to(`user:${member._id}`).emit('conversation_created', populated);
    }
  });

  res.json(populated);
});

app.get('/api/messages/:conversationId', auth, async (req, res) => {
  const { conversationId } = req.params;
  const m = await Message.find({ conversation: conversationId })
    .sort({ createdAt: 1 })
    .populate('sender');
  // Decrypt content if needed before sending to client
  const safe = m.map(toSafeMessage);
  // Filter out messages with no content and no attachments
  const filtered = safe.filter(msg => msg.content || (msg.attachments && msg.attachments.length > 0));
  res.json(filtered);
});

app.delete('/api/conversations/:id', auth, async (req, res) => {
  try {
    const conv = await Conversation.findById(req.params.id);
    if (!conv) return res.status(404).json({ error: 'Conversation not found' });

    // Check if user is a member
    if (!conv.members.some(m => String(m) === String(req.user._id))) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    // Delete all messages in this conversation
    await Message.deleteMany({ conversation: req.params.id });

    // Delete the conversation
    await Conversation.findByIdAndDelete(req.params.id);

    // Notify all members that conversation was deleted
    conv.members.forEach(memberId => {
      io.to(`user:${memberId}`).emit('conversation_deleted', { conversationId: req.params.id });
    });

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Clear conversation (for groups - clears messages from user's view only)
app.post('/api/conversations/:id/clear', auth, async (req, res) => {
  try {
    const conv = await Conversation.findById(req.params.id);
    if (!conv) return res.status(404).json({ error: 'Conversation not found' });

    // Check if user is a member
    if (!conv.members.some(m => String(m) === String(req.user._id))) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    // Note: In a real app, you'd track which messages each user has cleared
    // For now, we'll just return success and let the client clear locally
    // You could add a 'clearedBy' field to messages or create a separate collection

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Leave group or remove direct conversation
app.post('/api/conversations/:id/leave', auth, async (req, res) => {
  try {
    const conv = await Conversation.findById(req.params.id);
    if (!conv) return res.status(404).json({ error: 'Conversation not found' });

    // Check if user is a member
    if (!conv.members.some(m => String(m) === String(req.user._id))) {
      return res.status(403).json({ error: 'Not a member' });
    }

    if (conv.type === 'group') {
      // For groups: Remove user from members
      conv.members = conv.members.filter(m => String(m) !== String(req.user._id));
      await conv.save();

      // Notify remaining members
      conv.members.forEach(memberId => {
        io.to(`user:${memberId}`).emit('member_left', {
          conversationId: req.params.id,
          userId: req.user._id
        });
      });
    } else {
      // For direct conversations: Hide from user's view
      if (!conv.hiddenFor.includes(req.user._id)) {
        conv.hiddenFor.push(req.user._id);
        await conv.save();
      }
    }

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Add member to group
app.post('/api/conversations/:id/add-member', auth, async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId required' });

    const conv = await Conversation.findById(req.params.id);
    if (!conv) return res.status(404).json({ error: 'Conversation not found' });

    // Check if it's a group
    if (conv.type !== 'group') {
      return res.status(400).json({ error: 'Can only add members to groups' });
    }

    // Check if requester is a member
    if (!conv.members.some(m => String(m) === String(req.user._id))) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    // Check if user is already a member
    if (conv.members.some(m => String(m) === String(userId))) {
      return res.status(400).json({ error: 'User is already a member' });
    }

    // Add user to members
    conv.members.push(userId);
    await conv.save();

    // Notify all members including the new one
    const populated = await Conversation.findById(conv._id).populate('members');
    populated.members.forEach(memberId => {
      io.to(`user:${memberId._id}`).emit('member_added', {
        conversationId: req.params.id,
        userId,
        conversation: populated
      });
    });

    res.json({ success: true, conversation: populated });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Remove member from group (Admin only)
app.post('/api/conversations/:id/remove-member', auth, async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId required' });

    const conv = await Conversation.findById(req.params.id);
    if (!conv) return res.status(404).json({ error: 'Conversation not found' });

    if (conv.type !== 'group') {
      return res.status(400).json({ error: 'Can only remove members from groups' });
    }

    // Check if requester is admin (first member)
    if (String(conv.members[0]) !== String(req.user._id)) {
      return res.status(403).json({ error: 'Only admin can remove members' });
    }

    // Check if user to remove is in the group
    if (!conv.members.some(m => String(m) === String(userId))) {
      return res.status(400).json({ error: 'User is not a member' });
    }

    // Cannot remove self (use leave instead)
    if (String(userId) === String(req.user._id)) {
      return res.status(400).json({ error: 'Cannot remove yourself, use leave group' });
    }

    // Remove user
    conv.members = conv.members.filter(m => String(m) !== String(userId));
    await conv.save();

    // Notify all members (including the removed one)
    io.to(`user:${userId}`).emit('member_removed', {
      conversationId: req.params.id,
      userId: userId
    });

    conv.members.forEach(memberId => {
      io.to(`user:${memberId}`).emit('member_removed', {
        conversationId: req.params.id,
        userId: userId
      });
    });

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/messages/:id', auth, async (req, res) => {
  try {
    const msg = await Message.findById(req.params.id);
    if (!msg) return res.status(404).json({ error: 'Message not found' });

    // Only sender can delete
    if (String(msg.sender) !== String(req.user._id)) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    await Message.findByIdAndDelete(req.params.id);

    // Notify everyone in the conversation
    io.to(`conv:${msg.conversation}`).emit('message_deleted', { messageId: req.params.id, conversationId: msg.conversation });

    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Socket.IO auth for WebSocket connections
io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token;
  let u = null;
  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      u = await User.findById(payload.uid);
    } catch { }
  }
  if (!u) {
    const userId = socket.handshake.auth?.userId; // dev fallback
    if (userId) u = await User.findById(userId);
  }
  if (!u) return next(new Error('unauthorized'));
  socket.user = u;
  next();
});

io.on('connection', (socket) => {
  const user = socket.user;
  socket.join(`user:${user._id}`);

  // Mark user online and broadcast presence
  user.lastSeenAt = new Date();
  user.save().catch(() => { });
  io.emit('user_online', {
    userId: String(user._id),
    username: user.username,
    lastSeenAt: user.lastSeenAt,
  });

  socket.on('join_conversation', (conversationId) => {
    socket.join(`conv:${conversationId}`);
  });

  socket.on('leave_conversation', (conversationId) => {
    socket.leave(`conv:${conversationId}`);
  });

  socket.on('typing', ({ conversationId }) => {
    socket.to(`conv:${conversationId}`).emit('typing', { userId: String(user._id), conversationId });
  });

  socket.on('stop_typing', ({ conversationId }) => {
    socket.to(`conv:${conversationId}`).emit('stop_typing', { userId: String(user._id), conversationId });
  });

  socket.on('message_send', async ({ conversationId, content, tempId, attachments }) => {
    if (!content && (!attachments || attachments.length === 0)) return;

    const encContent = content ? encryptText(content) : '';

    // Parse attachments if it's a string (Socket.IO sometimes stringifies)
    let parsedAttachments = attachments;
    if (typeof attachments === 'string') {
      try {
        parsedAttachments = JSON.parse(attachments);
      } catch (e) {
        console.error('Failed to parse attachments:', e);
        parsedAttachments = [];
      }
    }

    const msg = new Message({
      conversation: conversationId,
      sender: user._id,
      contentEnc: encContent,
      tempId,
      attachments: parsedAttachments || []
    });
    await msg.save();

    await Conversation.findByIdAndUpdate(conversationId, {
      lastMessageAt: new Date(),
      hiddenFor: [] // Unhide for everyone
    });

    const populated = await Message.findById(msg._id).populate('sender');
    const safe = toSafeMessage(populated);
    io.to(`conv:${conversationId}`).emit('message_new', safe);
  });

  socket.on('message_delivered', async ({ messageId }) => {
    const m = await Message.findById(messageId);
    if (!m) return;
    if (!m.deliveredTo.map(String).includes(String(user._id))) {
      m.deliveredTo.push(user._id);
      await m.save();
    }
    io.to(`conv:${m.conversation}`).emit('message_update', { messageId, deliveredTo: m.deliveredTo });
  });

  socket.on('message_seen', async ({ conversationId }) => {
    const msgs = await Message.find({ conversation: conversationId, seenBy: { $ne: user._id } });
    for (const m of msgs) {
      m.seenBy.push(user._id);
      await m.save();
      io.to(`conv:${conversationId}`).emit('message_update', { messageId: String(m._id), seenBy: m.seenBy });
    }
  });

  // Audio / video call signaling
  socket.on('call_start', async ({ conversationId, kind }) => {
    try {
      if (!conversationId) return;
      const conv = await Conversation.findById(conversationId).populate('members');
      if (!conv) return;

      const isMember = conv.members.some(m => String(m._id) === String(user._id));
      if (!isMember) return;

      const callId = uuidv4();
      const payload = {
        callId,
        conversationId: String(conv._id),
        kind: kind === 'video' ? 'video' : 'audio',
        from: { _id: String(user._id), username: user.username, avatar: user.avatar },
        isGroup: conv.type === 'group',
      };

      // Caller joins call room
      socket.join(`call:${callId}`);

      // Notify caller that call is created
      socket.emit('call_started', payload);

      // Notify all other members (direct: only the other user, group: everyone else)
      conv.members
        .filter(m => String(m._id) !== String(user._id))
        .forEach(m => {
          io.to(`user:${m._id}`).emit('call_incoming', payload);
        });
    } catch (e) {
      console.error('call_start error', e);
    }
  });

  socket.on('call_accept', async ({ callId, conversationId }) => {
    try {
      if (!callId || !conversationId) return;

      // Join the shared call room
      socket.join(`call:${callId}`);

      // Find other sockets already in this call room to build the peer list
      const room = io.sockets.adapter.rooms.get(`call:${callId}`);
      const otherSocketIds = room ? [...room].filter(id => id !== socket.id) : [];
      const otherUserIds = [];
      for (const sid of otherSocketIds) {
        const s = io.sockets.sockets.get(sid);
        if (s?.user?._id) {
          otherUserIds.push(String(s.user._id));
        }
      }

      // Tell this user who is already in the call so they can create peer connections
      socket.emit('call_existing_participants', {
        callId,
        conversationId,
        userIds: otherUserIds,
      });

      // Tell others that this user has joined the call
      socket.to(`call:${callId}`).emit('call_peer_accepted', {
        callId,
        conversationId,
        userId: String(user._id),
      });
    } catch (e) {
      console.error('call_accept error', e);
    }
  });

  socket.on('call_signal', ({ callId, toUserId, data }) => {
    if (!callId || !toUserId || !data) return;
    io.to(`user:${toUserId}`).emit('call_signal', {
      callId,
      fromUserId: String(user._id),
      data,
    });
  });

  socket.on('call_end', ({ callId, conversationId }) => {
    if (!callId || !conversationId) return;
    const payload = {
      callId,
      conversationId,
      fromUserId: String(user._id),
    };
    // Notify everyone connected to this call and in the conversation room
    io.to(`call:${callId}`).emit('call_ended', payload);
    io.to(`conv:${conversationId}`).emit('call_ended', payload);
  });

  socket.on('call_leave', ({ callId }) => {
    if (!callId) return;
    socket.leave(`call:${callId}`);
    socket.to(`call:${callId}`).emit('call_user_left', {
      callId,
      userId: String(user._id),
    });
  });

  socket.on('call_participant_state', ({ callId, isMicOff, isCameraOff }) => {
    if (!callId) return;
    socket.to(`call:${callId}`).emit('call_participant_state', {
      callId,
      userId: String(user._id),
      isMicOff,
      isCameraOff
    });
  });

  socket.on('disconnect', async () => {
    const rooms = io.sockets.adapter.sids.get(socket.id);
    if (rooms) {
      rooms.forEach((room) => {
        if (room.startsWith('call:')) {
          const callId = room.split(':')[1];
          socket.to(room).emit('call_user_left', {
            callId,
            userId: String(user._id),
          });
        }
      });
    }

    user.lastSeenAt = new Date();
    await user.save().catch(() => { });

    io.emit('user_offline', {
      userId: String(user._id),
      username: user.username,
      lastSeenAt: user.lastSeenAt,
    });
  });
});

// Seed admin user if it doesn't exist
const seedAdminUser = async () => {
  console.log('Seeding admin user...');
  try {
    const adminEmail = 'admin@xevyte.com';
    const existingAdmin = await User.findOne({ email: adminEmail });

    if (!existingAdmin) {
      console.log('Admin user not found, creating...');
      const passwordHash = await bcrypt.hash('admin123', 10);
      const admin = new User({
        username: 'Admin',
        email: adminEmail,
        passwordHash,
        avatar: `https://api.dicebear.com/8.x/pixel-art/svg?seed=Admin`,
        isAdmin: true
      });
      await admin.save();
      console.log('✓ Admin user created (admin@xevyte.com / admin123)');
    } else {
      console.log('Admin user already exists');
      // Ensure existing admin has isAdmin flag
      if (!existingAdmin.isAdmin) {
        existingAdmin.isAdmin = true;
        await existingAdmin.save();
        console.log('✓ Admin flag updated for admin@xevyte.com');
      } else {
        console.log('✓ Admin user ready (admin@xevyte.com / admin123)');
      }
    }
  } catch (error) {
    console.error('Error seeding admin user:', error);
  }
};

const startServer = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('Connected to MongoDB');

    // Seed admin user
    await seedAdminUser();
  } catch (err) {
    console.error('Failed to connect to primary MongoDB:', err.message);
    // Fallback to local if primary fails and it wasn't already local
    if (MONGO_URI.includes('mongodb.net')) {
      console.log('Attempting fallback to local MongoDB...');
      try {
        await mongoose.connect('mongodb://127.0.0.1:27017/chatbot');
        console.log('Connected to local MongoDB fallback');

        // Seed admin user on fallback connection too
        await seedAdminUser();
      } catch (localErr) {
        console.error('Failed to connect to local MongoDB:', localErr.message);
        process.exit(1);
      }
    } else {
      process.exit(1);
    }
  }

  server.listen(PORT, () => console.log(`API http://localhost:${PORT}`));
};

startServer();

// Periodic heartbeat to update lastSeenAt for connected users
setInterval(() => {
  if (!io) return;
  io.sockets.sockets.forEach((socket) => {
    if (socket.user) {
      User.findByIdAndUpdate(socket.user._id, { lastSeenAt: new Date() })
        .catch(e => console.error('Heartbeat update error:', e.message));
    }
  });
}, 60 * 1000); // Every minute
