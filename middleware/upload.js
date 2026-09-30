// middleware/upload.js
const multer = require('multer');
const path = require('path');

const ALLOWED_MIME_TYPES = [
  'image/jpeg', 'image/png', 'image/gif', 'image/webp',
  'application/pdf',
  'text/plain',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'audio/webm', 'audio/mp3', 'audio/wav', 'audio/ogg', 'audio/mpeg', 'audio/mp4'
];

const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf', '.txt', '.doc', '.docx', '.webm', '.mp3', '.wav', '.ogg', '.m4a'];

// --- SWITCHED FROM DISK STORAGE TO MEMORY STORAGE ---
// This keeps file buffers in system memory for direct streaming to Pinata IPFS
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  const ext = path.extname(file.originalname).toLowerCase();
  const isAllowedMime = ALLOWED_MIME_TYPES.includes(file.mimetype);
  const isAllowedExt = ALLOWED_EXTENSIONS.includes(ext);

  if (isAllowedMime && isAllowedExt) {
    cb(null, true);
  } else {
    cb(new Error(`File type not allowed. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}`), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024, // 5MB
    files: 4,
  },
});

module.exports = upload;


// // middleware/upload.js
// const multer = require('multer');
// const path = require('path');
// const crypto = require('crypto');
// const fs = require('fs');

// const ALLOWED_MIME_TYPES = [
//   'image/jpeg', 'image/png', 'image/gif', 'image/webp',
//   'application/pdf',
//   'text/plain',
//   'application/msword',
//   'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
//   'audio/webm', 'audio/mp3', 'audio/wav', 'audio/ogg', 'audio/mpeg', 'audio/mp4'
// ];

// const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf', '.txt', '.doc', '.docx', '.webm', '.mp3', '.wav', '.ogg', '.m4a'];
// // Ensure upload directory exists
// const uploadDir = process.env.UPLOAD_PATH || './uploads';
// if (!fs.existsSync(uploadDir)) {
//   fs.mkdirSync(uploadDir, { recursive: true });
// }

// const storage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, uploadDir);
//   },
//   filename: (req, file, cb) => {
//     // Random hash name – strips original filename (metadata protection)
//     const hash = crypto.randomBytes(16).toString('hex');
//     const ext = path.extname(file.originalname).toLowerCase();
//     cb(null, hash + ext);
//   },
// });

// const fileFilter = (req, file, cb) => {
//   const ext = path.extname(file.originalname).toLowerCase();
//   const isAllowedMime = ALLOWED_MIME_TYPES.includes(file.mimetype);
//   const isAllowedExt = ALLOWED_EXTENSIONS.includes(ext);

//   if (isAllowedMime && isAllowedExt) {
//     cb(null, true);
//   } else {
//     cb(new Error(`File type not allowed. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}`), false);
//   }
// };

// const upload = multer({
//   storage,
//   fileFilter,
//   limits: {
//     fileSize: parseInt(process.env.MAX_FILE_SIZE) || 5 * 1024 * 1024, // 5MB
//     files: 4,
//   },
// });

// module.exports = upload;
