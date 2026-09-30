// models/Report.js
const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
  // Public acknowledgement number given to reporter
  ackNumber: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },

  // Encrypted sensitive fields
  reporterName: { type: String, default: null },     // AES-256 encrypted (if provided)
  reporterContact: { type: String, default: null },  // AES-256 encrypted (if provided)

  // Report content
  title: { type: String, required: true, maxlength: 200 },
  description: { type: String, required: true, maxlength: 5000 },

  category: {
    type: String,
    required: true,
    enum: ['corruption', 'fraud', 'harassment', 'cybercrime', 'environmental', 'financial', 'other'],
  },

  severity: {
    type: String,
    required: true,
    enum: ['low', 'medium', 'high', 'critical'],
  },

  accusedOrganization: { type: String, maxlength: 300 },
  accusedPersons: [{ type: String, maxlength: 100 }],
  location: { type: String, maxlength: 200 },

    // Evidence files (stored securely with Decentralized IPFS and Blockchain metrics)
  evidenceFiles: [{
    originalName: String,
    storedName: String, // You can assign an internal tracking tracking name here
    mimeType: String,
    size: Number,
    ipfsCID: { type: String, default: null },   // Added for IPFS Decentralized Identifier
    fileHash: { type: String, default: null },  // Added for SHA-256 Ledger anchoring
    uploadedAt: { type: Date, default: Date.now },
  }],

  // Anonymity & Security
  ipHash: { type: String },           // SHA-256 hashed IP (never raw)
  userAgent: { type: String },        // browser info only

  // Risk scoring
  riskScore: {
    score: { type: Number, default: 0 },
    level: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'low' },
    factors: [String],
  },

  // Threat detection
  threatFlags: {
    isDuplicate: { type: Boolean, default: false },
    isSpam: { type: Boolean, default: false },
    suspicionScore: { type: Number, default: 0 },
    flags: [String],
  },

  // Integrity chain
  contentHash: { type: String },      // SHA-256 of report content
  previousHash: { type: String, default: '0' }, // blockchain-style

  // Simulated Blockchain — PDF integrity verification
  blockchain: {
    blockId: { type: Number, default: null },
    hash: { type: String, default: null },
    previousHash: { type: String, default: null },
    pdfHash: { type: String, default: null },       // SHA-256 of the PDF file
    timestamp: { type: Date, default: null },
    verified: { type: Boolean, default: false },
  },

  // Status tracking
  status: {
    type: String,
    enum: ['pending', 'under_review', 'investigating', 'resolved', 'dismissed'],
    default: 'pending',
  },

  adminNotes: { type: String, maxlength: 2000 },
  assignedTo: { type: String },

  // Timestamps
  submittedAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  resolvedAt: { type: Date },

  // Secure Dead Drop Messaging System
  messages: [{
    sender: { type: String, enum: ['user', 'admin'], required: true },
    content: {
      iv: { type: String, required: true },
      content: { type: String, required: true }
    },
    timestamp: { type: Date, default: Date.now }
  }],

  // Voice Evidence
  audioEvidence: [{
    filePath: { type: String, required: true },
    uploadedAt: { type: Date, default: Date.now }
  }],

}, { timestamps: false });

// Update the updatedAt on save
reportSchema.pre('save', function (next) {
  this.updatedAt = new Date();
  next();
});

module.exports = mongoose.model('Report', reportSchema);
