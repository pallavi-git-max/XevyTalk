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
import { GridFSBucket } from 'mongodb';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const app = express();

// Enhanced CORS configuration for production
const allowedOrigins = [
  'https://xevytalk-client.onrender.com',
  'http://localhost:5173',
  'http://localhost:5174',
  'http://localhost:3000',
  'http://127.0.0.1:5173',
  'http://127.0.0.1:5174'
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    // Allow localhost on any port for development
    if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
      return callback(null, true);
    }
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

// File upload limits and allowed types
const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25 MB
const ALLOWED_FILE_TYPES = [
  'image/jpeg', 'image/png', 'image/gif', 'image/webp',
  'application/pdf',
  'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'video/mp4', 'video/quicktime', 'video/x-msvideo',
  'audio/mpeg', 'audio/mp3', 'audio/wav', 'audio/ogg',
  'text/plain', 'text/csv'
];

// Configure Multer to use memory storage (files will be stored in MongoDB GridFS)
const upload = multer({ 
  storage: multer.memoryStorage(), 
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    if (ALLOWED_FILE_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`File type ${file.mimetype} not allowed. Allowed types: ${ALLOWED_FILE_TYPES.join(', ')}`), false);
    }
  }
});

// GridFS bucket will be initialized after MongoDB connection
let gridFSBucket = null;

const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: (origin, callback) => {
      // Allow all localhost origins for development
      if (!origin || origin.includes('localhost') || origin.includes('127.0.0.1')) {
        return callback(null, true);
      }
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      callback(null, true);
    },
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
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
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
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to XevyTalk</title>
        <style>
          body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background-color: #f4f4f5; margin: 0; padding: 0; }
          .wrapper { width: 100%; background-color: #f4f4f5; padding: 40px 0; }
          .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); }
          .header { background-color: #ffffff; padding: 40px 40px 20px; text-align: center; }
          .logo { font-size: 32px; font-weight: 800; color: #0891b2; text-decoration: none; display: inline-block; }
          .content { padding: 20px 40px 40px; }
          .greeting { font-size: 24px; font-weight: 700; color: #18181b; margin-bottom: 16px; }
          .text { color: #52525b; font-size: 16px; margin-bottom: 24px; }
          .credentials-box { background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 24px; margin-bottom: 24px; }
          .credential-row { margin-bottom: 12px; }
          .credential-row:last-child { margin-bottom: 0; }
          .label { font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; font-weight: 600; margin-bottom: 4px; }
          .value { font-family: 'Monaco', 'Consolas', monospace; font-size: 16px; color: #0f172a; font-weight: 500; background: #fff; padding: 8px 12px; border-radius: 6px; border: 1px solid #e2e8f0; display: inline-block; }
          .button-container { text-align: center; margin-top: 32px; margin-bottom: 32px; }
          .button { background-color: #0891b2; color: #ffffff; padding: 14px 32px; text-decoration: none; border-radius: 50px; font-weight: 600; font-size: 16px; display: inline-block; transition: background-color 0.2s; }
          .button:hover { background-color: #0e7490; }
          .alert { background-color: #fff7ed; border-left: 4px solid #f97316; padding: 16px; border-radius: 4px; margin-bottom: 24px; }
          .alert-text { color: #9a3412; font-size: 14px; margin: 0; }
          .footer { background-color: #f8fafc; padding: 24px; text-align: center; border-top: 1px solid #e2e8f0; }
          .footer-text { color: #94a3b8; font-size: 12px; margin: 0; }
        </style>
      </head>
      <body>
        <div class="wrapper">
          <div class="container">
            <div class="header">
              <div class="logo">💬 XevyTalk</div>
            </div>
            <div class="content">
              <h1 class="greeting">Hello, ${username}!</h1>
              <p class="text">Welcome to the team. Your account has been created successfully. Here are your temporary login credentials:</p>
              
              <div class="credentials-box">
                <div class="credential-row">
                  <div class="label">Email Address</div>
                  <div class="value">${email}</div>
                </div>
                <div class="credential-row">
                  <div class="label">Temporary Password</div>
                  <div class="value">${password}</div>
                </div>
              </div>

              <div class="alert">
                <p class="alert-text"><strong>Security Notice:</strong> You will be required to change this password immediately upon your first login.</p>
              </div>

              <div class="button-container">
                <a href="http://localhost:5173/login" class="button">Login to Account</a>
              </div>
              
              <p class="text" style="font-size: 14px; color: #71717a; text-align: center;">If the button doesn't work, copy this link:<br><a href="http://localhost:5173/login" style="color: #0891b2;">http://localhost:5173/login</a></p>
            </div>
            <div class="footer">
              <p class="footer-text">&copy; ${new Date().getFullYear()} XevyTalk. All rights reserved.</p>
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
  isAdmin: { type: Boolean, default: false },
  createdByAdmin: { type: Boolean, default: false }, // Track if user was created by admin
  mustChangePassword: { type: Boolean, default: false } // Force password change on first login
}, { timestamps: true });

const conversationSchema = new mongoose.Schema({
  type: { type: String, enum: ['direct', 'group'], required: true },
  name: { type: String },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  lastMessageAt: { type: Date, default: Date.now },
  hiddenFor: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
}, { timestamps: true });

// Attachment subdocument schema
const attachmentSchema = new mongoose.Schema({
  fileId: { type: String, required: true },
  fileURL: { type: String, required: true },
  name: { type: String, required: true },
  type: { type: String, required: true },
  size: { type: Number, required: true },
  thumbnailURL: { type: String, default: null }
}, { _id: false });

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
  attachments: [attachmentSchema],
  editedAt: { type: Date },
}, { timestamps: true });

// Upload session schema for temporary upload tracking
const uploadSessionSchema = new mongoose.Schema({
  sessionId: { type: String, required: true, unique: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fileName: { type: String },
  fileType: { type: String },
  fileSize: { type: Number },
  expiresAt: { type: Date, default: () => new Date(Date.now() + 3600000) }, // 1 hour expiry
  uploaded: { type: Boolean, default: false },
  fileId: { type: String }, // Set after upload completes
  fileURL: { type: String }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);
const Conversation = mongoose.model('Conversation', conversationSchema);
const Message = mongoose.model('Message', messageSchema);
const UploadSession = mongoose.model('UploadSession', uploadSessionSchema);

// Normalize message shape for API / socket responses.
// If encrypted content exists, decrypt it into .content field.
const toSafeMessage = (m, req = null) => {
  if (!m) return m;
  const obj = m.toObject ? m.toObject() : { ...m };
  if (obj.contentEnc) {
    const decrypted = decryptText(obj.contentEnc);
    if (decrypted) obj.content = decrypted;
  }
  // Add URLs to attachments if they exist
  if (obj.attachments && obj.attachments.length > 0) {
    const protocol = process.env.NODE_ENV === 'production' ? 'https' : 'http';
    const host = req ? (req.get('host') || `localhost:${PORT}`) : `localhost:${PORT}`;
    obj.attachments = obj.attachments.map(att => ({
      fileId: att.fileId,
      fileURL: att.fileURL || att.url || `${protocol}://${host}/api/files/${att.fileId}`,
      url: att.fileURL || att.url || `${protocol}://${host}/api/files/${att.fileId}`, // For backward compatibility
      name: att.name,
      type: att.type,
      size: att.size,
      thumbnailURL: att.thumbnailURL || null
    }));
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

  // Only allow admin@xevyte.com to register
  const normalizedEmail = email.toLowerCase().trim();
  console.log(`Registration attempt for: '${email}' (normalized: '${normalizedEmail}')`);

  if (normalizedEmail !== 'admin@xevyte.com') {
    console.log(`Registration blocked for: '${email}'`);
    return res.status(403).json({ error: 'Registration is disabled. Please contact admin for account creation.' });
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
    isAdmin: true,
    createdByAdmin: false // Admin creates themselves
  });
  await u.save();
  res.json({ token: signToken(u), user: u });
});

app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-passwordHash');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
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

  // Check if user was created by admin or is admin
  if (!u.createdByAdmin && !u.isAdmin) {
    return res.status(401).json({ error: 'Invalid credentials. Please contact admin for account creation.' });
  }

  const ok = await bcrypt.compare(password, u.passwordHash);
  if (!ok) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Set isAdmin flag if email is admin@xevyte.com
  if (email === 'admin@xevyte.com' && !u.isAdmin) {
    u.isAdmin = true;
    await u.save();
    console.log(`✓ Admin flag set for ${email}`);
  }

  res.json({ token: signToken(u), user: u });
});

app.post('/api/auth/change-password', auth, async (req, res) => {
  const { newPassword } = req.body;

  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long' });
  }

  try {
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const passwordHash = await bcrypt.hash(newPassword, 10);
    user.passwordHash = passwordHash;
    user.mustChangePassword = false;
    await user.save();

    res.json({ message: 'Password updated successfully', user });
  } catch (error) {
    console.error('Error changing password:', error);
    res.status(500).json({ error: 'Failed to update password' });
  }
});

// ============================================================================
// WHATSAPP-LIKE FILE UPLOAD SYSTEM
// ============================================================================

// Step 1: Create upload session - returns uploadURL and fileId
app.post('/api/media/create-upload-session', auth, async (req, res) => {
  try {
    const { fileName, fileType, fileSize } = req.body;

    if (!fileName || !fileType || !fileSize) {
      return res.status(400).json({ error: 'fileName, fileType, and fileSize are required' });
    }

    // Validate file size
    if (fileSize > MAX_FILE_SIZE) {
      return res.status(400).json({ error: `File size exceeds maximum limit of ${MAX_FILE_SIZE / 1024 / 1024}MB` });
    }

    // Validate file type
    if (!ALLOWED_FILE_TYPES.includes(fileType)) {
      return res.status(400).json({ error: `File type ${fileType} not allowed` });
    }

    // Generate unique session ID
    const sessionId = `${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;

    // Create upload session
    const session = new UploadSession({
      sessionId,
      userId: req.user._id,
      fileName,
      fileType,
      fileSize
    });
    await session.save();

    // Generate upload URL and final file URL
    const protocol = process.env.NODE_ENV === 'production' ? 'https' : 'http';
    const host = req.get('host') || `localhost:${PORT}`;
    const uploadURL = `${protocol}://${host}/api/media/upload/${sessionId}`;
    const finalFileURL = `${protocol}://${host}/api/files/${sessionId}`; // Will be updated after upload

    res.json({
      sessionId,
      uploadURL,
      finalFileURL, // Placeholder, will be actual file URL after upload
      fileId: sessionId, // Temporary, will be GridFS ID after upload
      expiresAt: session.expiresAt
    });
  } catch (error) {
    console.error('Error creating upload session:', error);
    res.status(500).json({ error: 'Failed to create upload session' });
  }
});

// Step 2: Direct file upload endpoint (frontend uploads here)
app.post('/api/media/upload/:sessionId', auth, upload.single('file'), async (req, res) => {
  try {
    const { sessionId } = req.params;

    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    if (!gridFSBucket) {
      return res.status(500).json({ error: 'File storage not initialized' });
    }

    // Find and validate session
    const session = await UploadSession.findOne({ sessionId, userId: req.user._id });
    if (!session) {
      return res.status(404).json({ error: 'Upload session not found or expired' });
    }

    if (session.uploaded) {
      return res.status(400).json({ error: 'File already uploaded for this session' });
    }

    if (new Date() > session.expiresAt) {
      return res.status(400).json({ error: 'Upload session expired' });
    }

    // Validate file matches session
    if (req.file.size !== session.fileSize || req.file.mimetype !== session.fileType) {
      return res.status(400).json({ error: 'File does not match session parameters' });
    }

    // Upload to GridFS
    const filename = `${Date.now()}-${Math.round(Math.random() * 1E9)}-${session.fileName}`;
    const uploadStream = gridFSBucket.openUploadStream(filename, {
      contentType: session.fileType,
      metadata: {
        originalName: session.fileName,
        mimeType: session.fileType,
        uploadedBy: String(req.user._id),
        uploadedAt: new Date(),
        sessionId: sessionId
      }
    });

    return new Promise((resolve, reject) => {
      uploadStream.on('finish', async () => {
        try {
          const fileId = uploadStream.id.toString();
          const protocol = process.env.NODE_ENV === 'production' ? 'https' : 'http';
          const host = req.get('host') || `localhost:${PORT}`;
          const fileURL = `${protocol}://${host}/api/files/${fileId}`;

          // Update session with file info
          session.uploaded = true;
          session.fileId = fileId;
          session.fileURL = fileURL;
          await session.save();

          res.json({
            success: true,
            fileId,
            fileURL,
            fileName: session.fileName,
            fileType: session.fileType,
            fileSize: session.fileSize
          });
          resolve();
        } catch (error) {
          console.error('Error saving session:', error);
          if (!res.headersSent) {
            res.status(500).json({ error: 'Failed to complete upload' });
          }
          reject(error);
        }
      });

      uploadStream.on('error', (error) => {
        console.error('GridFS upload error:', error);
        if (!res.headersSent) {
          res.status(500).json({ error: 'Failed to upload file' });
        }
        reject(error);
      });

      uploadStream.end(req.file.buffer);
    });
  } catch (error) {
    console.error('Upload error:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to upload file' });
    }
  }
});

// Step 3: Send message with file metadata (no file content)
app.post('/api/messages/send', auth, async (req, res) => {
  try {
    const { conversationId, messageText, fileId, fileURL, fileName, fileType, fileSize, thumbnailURL } = req.body;

    if (!conversationId) {
      return res.status(400).json({ error: 'conversationId is required' });
    }

    // Verify conversation exists and user is a member
    const conv = await Conversation.findById(conversationId);
    if (!conv) {
      return res.status(404).json({ error: 'Conversation not found' });
    }

    if (!conv.members.some(m => String(m) === String(req.user._id))) {
      return res.status(403).json({ error: 'Not a member of this conversation' });
    }

    // If file is included, verify it was uploaded via session
    let attachments = [];
    if (fileId && fileURL) {
      const session = await UploadSession.findOne({ 
        fileId, 
        userId: req.user._id, 
        uploaded: true 
      });

      if (!session) {
        return res.status(400).json({ error: 'File not found or not uploaded' });
      }

      // Create attachment object with explicit types
      attachments = [{
        fileId: String(fileId),
        fileURL: String(fileURL || session.fileURL),
        name: String(fileName || session.fileName),
        type: String(fileType || session.fileType),
        size: Number(fileSize || session.fileSize),
        thumbnailURL: thumbnailURL ? String(thumbnailURL) : null
      }];
    }

    // Create message
    const content = messageText || '';
    const encContent = content ? encryptText(content) : '';
    const tempId = Math.random().toString(36).slice(2);

    // Ensure attachments is properly formatted
    const attachmentsArray = attachments && attachments.length > 0 ? attachments : [];
    
    // Validate and clean attachments
    const cleanAttachments = attachmentsArray.map(att => {
      // Handle if attachment is stringified
      if (typeof att === 'string') {
        try {
          att = JSON.parse(att);
        } catch (e) {
          console.error('Failed to parse attachment:', att);
          return null;
        }
      }
      
      return {
        fileId: String(att.fileId || ''),
        fileURL: String(att.fileURL || att.url || ''),
        name: String(att.name || 'file'),
        type: String(att.type || 'application/octet-stream'),
        size: Number(att.size || 0),
        thumbnailURL: att.thumbnailURL ? String(att.thumbnailURL) : null
      };
    }).filter(att => att && att.fileId); // Remove invalid attachments
    
    const msg = new Message({
      conversation: conversationId,
      sender: req.user._id,
      contentEnc: encContent,
      content: content,
      tempId,
      attachments: cleanAttachments
    });

    try {
      await msg.save();
    } catch (saveError) {
      console.error('Message save error:', saveError);
      console.error('Attachments data:', JSON.stringify(cleanAttachments, null, 2));
      throw saveError;
    }

    // Update conversation
    await Conversation.findByIdAndUpdate(conversationId, {
      lastMessageAt: new Date(),
      hiddenFor: []
    });

    // Populate and send response
    const populated = await Message.findById(msg._id).populate('sender');
    const safe = toSafeMessage(populated, req);

    // Broadcast via Socket.IO (metadata only, no file content)
    io.to(`conv:${conversationId}`).emit('message_new', safe);

    res.json(safe);
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ error: error.message || 'Failed to send message' });
  }
});

// Download file from MongoDB GridFS
app.get('/api/files/:fileId', async (req, res) => {
  if (!gridFSBucket) {
    return res.status(500).json({ error: 'File storage not initialized' });
  }

  try {
    const fileId = req.params.fileId;
    let objectId;
    
    // Convert string ID to ObjectId
    try {
      objectId = new mongoose.Types.ObjectId(fileId);
    } catch (error) {
      return res.status(400).json({ error: 'Invalid file ID' });
    }
    
    // Check if file exists
    const files = await gridFSBucket.find({ _id: objectId }).toArray();
    if (files.length === 0) {
      return res.status(404).json({ error: 'File not found' });
    }

    const file = files[0];
    const downloadStream = gridFSBucket.openDownloadStream(objectId);

    // Set appropriate headers
    res.set('Content-Type', file.metadata?.mimeType || 'application/octet-stream');
    res.set('Content-Disposition', `inline; filename="${encodeURIComponent(file.metadata?.originalName || file.filename)}"`);
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Cross-Origin-Resource-Policy', 'cross-origin');

    downloadStream.pipe(res);

    downloadStream.on('error', (error) => {
      console.error('GridFS download error:', error);
      if (!res.headersSent) {
        res.status(500).json({ error: 'Failed to download file' });
      }
    });
  } catch (error) {
    console.error('Download error:', error);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to download file' });
    }
  }
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

    // Check if email already exists
    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    // Generate a random 8-character password
    const randomPassword = crypto.randomBytes(4).toString('hex'); // 8 character hex string
    const passwordHash = await bcrypt.hash(randomPassword, 10);

    const newUser = new User({
      username,
      email,
      passwordHash,
      avatar: `https://api.dicebear.com/8.x/pixel-art/svg?seed=${encodeURIComponent(username)}`,
      isAdmin: false,
      createdByAdmin: true, // Mark as created by admin
      mustChangePassword: true // Force password change
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

// Admin-only: Get all users created by admin
app.get('/api/admin/users', auth, async (req, res) => {
  try {
    // Check if user is admin
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: 'Unauthorized. Admin access required.' });
    }

    // Get all users created by admin, sorted alphabetically by username
    const users = await User.find({ createdByAdmin: true })
      .select('-passwordHash') // Exclude password hash
      .sort({ username: 1 }); // Sort alphabetically

    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch users' });
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
  try {
    const { conversationId } = req.params;
    const messages = await Message.find({ conversation: conversationId })
      .sort({ createdAt: 1 })
      .populate('sender');
    // Decrypt content and add attachment URLs
    const safeMessages = messages.map(m => toSafeMessage(m, req));
    // Filter out messages with no content and no attachments
    const filtered = safeMessages.filter(msg => msg.content || (msg.attachments && msg.attachments.length > 0));
    res.json(filtered);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
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

// Edit a message (sender only)
app.put('/api/messages/:id', auth, async (req, res) => {
  try {
    const { content } = req.body || {};
    if (!content || !String(content).trim()) {
      return res.status(400).json({ error: 'content required' });
    }

    const msg = await Message.findById(req.params.id);
    if (!msg) return res.status(404).json({ error: 'Message not found' });

    // Only sender can edit
    if (String(msg.sender) !== String(req.user._id)) {
      return res.status(403).json({ error: 'Not authorized' });
    }

    const encContent = encryptText(content);
    msg.contentEnc = encContent;
    msg.content = content;
    msg.editedAt = new Date();
    await msg.save();

    const safe = toSafeMessage(msg, req);

    io.to(`conv:${msg.conversation}`).emit('message_update', {
      messageId: String(msg._id),
      content: safe.content,
      editedAt: msg.editedAt
    });

    res.json(safe);
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

  // Socket.IO message_send - ONLY for text messages or already-uploaded file metadata
  // File uploads MUST use REST API /api/messages/send after uploading via /api/media/upload/:sessionId
  socket.on('message_send', async ({ conversationId, content, tempId, attachments }) => {
    // Only allow text-only messages via WebSocket
    // File attachments must be sent via REST API after upload
    if (!content && (!attachments || attachments.length === 0)) return;

    const encContent = content ? encryptText(content) : '';

    // For WebSocket, only accept metadata-only attachments (already uploaded files)
    // Attachments should only contain fileId, fileURL, name, type, size - NO file content
    let parsedAttachments = [];
    if (attachments) {
      try {
        parsedAttachments = typeof attachments === 'string' ? JSON.parse(attachments) : attachments;
        
        // Validate that attachments only contain metadata, not file content
        parsedAttachments = parsedAttachments
          .filter(att => att.fileId && att.fileURL) // Must have fileId and fileURL (already uploaded)
          .map(att => ({
            fileId: att.fileId,
            fileURL: att.fileURL,
            name: att.name || 'file',
            type: att.type || 'application/octet-stream',
            size: att.size || 0,
            thumbnailURL: att.thumbnailURL || null
          }));
      } catch (e) {
        console.error('Failed to parse attachments:', e);
        parsedAttachments = [];
      }
    }

    const msg = new Message({
      conversation: conversationId,
      sender: user._id,
      contentEnc: encContent,
      content: content || '',
      tempId,
      attachments: parsedAttachments
    });
    await msg.save();

    await Conversation.findByIdAndUpdate(conversationId, {
      lastMessageAt: new Date(),
      hiddenFor: []
    });

    const populated = await Message.findById(msg._id).populate('sender');
    
    // Generate URLs for attachments (metadata only)
    const protocol = process.env.NODE_ENV === 'production' ? 'https' : 'http';
    const safe = toSafeMessage(populated);
    if (safe.attachments && safe.attachments.length > 0) {
      safe.attachments = safe.attachments.map(att => ({
        ...att,
        url: att.fileURL || att.url || `${protocol}://localhost:${PORT}/api/files/${att.fileId}`
      }));
    }
    
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
    // Add connection options for better reliability
    const connectionOptions = {
      serverSelectionTimeoutMS: 10000, // Timeout after 10s instead of 30s
      socketTimeoutMS: 45000, // Close sockets after 45s of inactivity
      retryWrites: true,
      w: 'majority'
    };

    console.log('Connecting to MongoDB...');
    await mongoose.connect(MONGO_URI, connectionOptions);
    console.log('Connected to MongoDB successfully');
    
    // Initialize GridFS bucket for file storage
    const db = mongoose.connection.db;
    gridFSBucket = new GridFSBucket(db, { bucketName: 'files' });
    console.log('GridFS bucket initialized for file storage');
  } catch (err) {
    console.error('Failed to connect to MongoDB:', err.message);
    console.error('Error details:', err);
    
    // Check if it's a DNS/network error
    if (err.message.includes('ESERVFAIL') || err.message.includes('queryTxt') || err.message.includes('ENOTFOUND')) {
      console.error('\n⚠️  DNS Resolution Error - Cannot find MongoDB Atlas cluster:');
      console.error('   - Cluster URL:', MONGO_URI.replace(/:[^:@]+@/, ':****@'));
      console.error('\n   Possible issues:');
      console.error('   1. Cluster might be paused or deleted in MongoDB Atlas');
      console.error('   2. Cluster name/URL might be incorrect');
      console.error('   3. Network/DNS connectivity issue');
      console.error('\n   Solutions:');
      console.error('   → Go to MongoDB Atlas dashboard (https://cloud.mongodb.com)');
      console.error('   → Check if cluster is running (not paused)');
      console.error('   → Copy the correct connection string from Atlas');
      console.error('   → Verify Network Access allows your IP address');
      console.error('\n   Trying fallback to local MongoDB...');
      
      // Try local MongoDB as fallback
      try {
        const localURI = 'mongodb://127.0.0.1:27017/chatbot';
        console.log('Connecting to local MongoDB:', localURI);
        await mongoose.connect(localURI, { serverSelectionTimeoutMS: 5000 });
        console.log('✓ Connected to local MongoDB (fallback)');
        
        const db = mongoose.connection.db;
        gridFSBucket = new GridFSBucket(db, { bucketName: 'files' });
        console.log('GridFS bucket initialized for file storage');
        return; // Exit early, local connection successful
      } catch (localErr) {
        console.error('\n✗ Local MongoDB fallback also failed:', localErr.message);
        console.error('\n   Please fix MongoDB Atlas connection or start local MongoDB');
      }
    } else if (err.message.includes('authentication')) {
      console.error('\n⚠️  Authentication Error:');
      console.error('   - Check MongoDB username and password in .env file');
      console.error('   - Verify database user has correct permissions in Atlas');
    }
    
    process.exit(1);
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`API http://localhost:${PORT}`);
    console.log(`Server listening on all interfaces (0.0.0.0:${PORT})`);
  });
  
  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.error(`Port ${PORT} is already in use. Please stop the other process or use a different port.`);
      process.exit(1);
    } else {
      console.error('Server error:', err);
    }
  });
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
