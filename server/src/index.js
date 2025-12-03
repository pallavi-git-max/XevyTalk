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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// Ensure uploads directory exists
const uploadDir = path.join(__dirname, '../uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Serve uploaded files
app.use('/uploads', express.static(uploadDir));

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
  cors: { origin: true, credentials: true }
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

// Models
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  avatar: { type: String },
  lastSeenAt: { type: Date, default: Date.now },
  passwordHash: { type: String },
  email: { type: String },
  phone: { type: String },
  address: { type: String }
}, { timestamps: true });

const conversationSchema = new mongoose.Schema({
  type: { type: String, enum: ['direct', 'group'], required: true },
  name: { type: String },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  lastMessageAt: { type: Date, default: Date.now }
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
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const exists = await User.findOne({ username });
  if (exists) return res.status(409).json({ error: 'username already exists' });
  const passwordHash = await bcrypt.hash(password, 10);
  const u = new User({ username, passwordHash, avatar: `https://api.dicebear.com/8.x/pixel-art/svg?seed=${encodeURIComponent(username)}` });
  await u.save();
  res.json({ token: signToken(u), user: u });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  const u = await User.findOne({ username });
  if (!u || !u.passwordHash) return res.status(401).json({ error: 'invalid credentials' });
  const ok = await bcrypt.compare(password, u.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  res.json({ token: signToken(u), user: u });
});

app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
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

app.get('/api/conversations', auth, async (req, res) => {
  let list = await Conversation.find({ members: req.user._id })
    .sort({ updatedAt: -1 })
    .populate('members')
    .limit(50);
  list = list.filter(c => !(c.type === 'group' && (String(c.name || '').trim().toLowerCase() === 'lobby')))
  res.json(list);
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
  res.json(safe);
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

    const msg = new Message({
      conversation: conversationId,
      sender: user._id,
      contentEnc: encContent,
      tempId,
      attachments
    });
    await msg.save();

    await Conversation.findByIdAndUpdate(conversationId, { lastMessageAt: new Date() });

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

const startServer = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('Connected to MongoDB');
  } catch (err) {
    console.error('Failed to connect to primary MongoDB:', err.message);
    // Fallback to local if primary fails and it wasn't already local
    if (MONGO_URI.includes('mongodb.net')) {
      console.log('Attempting fallback to local MongoDB...');
      try {
        await mongoose.connect('mongodb://127.0.0.1:27017/chatbot');
        console.log('Connected to local MongoDB fallback');
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
