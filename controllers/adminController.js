// controllers/adminController.js
const Admin = require('../models/Admin');
const Report = require('../models/Report');
const AuditLog = require('../models/AuditLog');
const { encrypt, decrypt } = require('../utils/encryption');
const { logAction } = require('../services/auditService');
const logger = require('../utils/logger');
// const { contract } = require('../utils/blockchain');


// NEW DEPS FOR BLOCKCHAIN ACCESS CONTROL AND IPFS RETRIEVAL
const axios = require('axios');
const crypto = require('crypto');
const { contract } = require('../utils/blockchain');

// GET /admin/login
exports.showLogin = (req, res) => {
  res.render('admin/login', {
    title: 'Admin Login – SecureVoice',
    csrfToken: req.csrfToken(),
    error: null,
  });
};

// POST /admin/login
exports.login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const admin = await Admin.findOne({ email: email?.toLowerCase(), isActive: true });
    if (!admin || !(await admin.comparePassword(password))) {
      logger.warn(`Failed admin login attempt for: ${email}`);
      return res.render('admin/login', {
        title: 'Admin Login – SecureVoice',
        csrfToken: req.csrfToken(),
        error: 'Invalid credentials.',
      });
    }

    admin.lastLogin = new Date();
    await admin.save();

    req.session.adminId = admin._id;
    req.session.adminEmail = admin.email;
    req.session.adminName = admin.name;
    req.session.adminRole = admin.role;

    await logAction({
      adminId: admin._id,
      adminEmail: admin.email,
      action: 'ADMIN_LOGIN',
      details: 'Admin logged in',
      ip: req.ip,
    });

    logger.info(`Admin login: ${admin.email}`);
    res.redirect('/admin/dashboard');
  } catch (err) {
    logger.error('Admin login error:', err);
    res.render('admin/login', {
      title: 'Admin Login – SecureVoice',
      csrfToken: req.csrfToken(),
      error: 'Server error. Try again.',
    });
  }
};

// POST /admin/logout
exports.logout = async (req, res) => {
  await logAction({
    adminId: req.session.adminId,
    adminEmail: req.session.adminEmail,
    action: 'ADMIN_LOGOUT',
    ip: req.ip,
  });
  req.session.destroy();
  res.redirect('/admin/login');
};

// GET /admin/dashboard
exports.dashboard = async (req, res) => {
  try {
    const [
      totalReports,
      pendingReports,
      highRiskCount,
      criticalRiskCount,
      suspiciousCount,
      recentReports,
      recentAuditLogs,
      categoryStats,
      statusStats,
    ] = await Promise.all([
      Report.countDocuments(),
      Report.countDocuments({ status: 'pending' }),
      Report.countDocuments({ 'riskScore.level': 'high' }),
      Report.countDocuments({ 'riskScore.level': 'critical' }),
      Report.countDocuments({ 'threatFlags.suspicionScore': { $gte: 50 } }),
      Report.find().sort({ submittedAt: -1 }).limit(8).select('ackNumber title category severity riskScore status submittedAt threatFlags'),
      AuditLog.find().sort({ timestamp: -1 }).limit(10),
      Report.aggregate([{ $group: { _id: '$category', count: { $sum: 1 } } }]),
      Report.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }]),
    ]);

    res.render('admin/dashboard', {
      title: 'Security Dashboard – SecureVoice',
      admin: { name: req.session.adminName, role: req.session.adminRole },
      stats: {
        totalReports,
        pendingReports,
        highRiskCount,
        criticalRiskCount,
        suspiciousCount,
        resolvedReports: (statusStats.find(s => s._id === 'resolved') || {}).count || 0,
      },
      recentReports,
      recentAuditLogs,
      categoryStats,
      statusStats,
    });
  } catch (err) {
    logger.error('Dashboard error:', err);
    res.render('error', { title: 'Error', message: 'Dashboard load failed.', code: 500 });
  }
};

// GET /admin/reports
exports.listReports = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 15;
    const skip = (page - 1) * limit;

    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    if (req.query.risk) filter['riskScore.level'] = req.query.risk;
    if (req.query.category) filter.category = req.query.category;

    const [reports, total] = await Promise.all([
      Report.find(filter).sort({ submittedAt: -1 }).skip(skip).limit(limit),
      Report.countDocuments(filter),
    ]);

    res.render('admin/reports', {
      title: 'All Reports',
      admin: { name: req.session.adminName },
      reports,
      currentPage: page,
      totalPages: Math.ceil(total / limit),
      total,
      query: req.query,
    });
  } catch (err) {
    logger.error('List reports error:', err);
    res.render('error', { title: 'Error', message: 'Could not load reports.', code: 500 });
  }
};

// GET /admin/reports/:id
exports.viewReport = async (req, res) => {
  try {
    const report = await Report.findById(req.params.id);
    if (!report) return res.render('error', { title: '404', message: 'Report not found.', code: 404 });

    // Decrypt sensitive fields for admin view
    const decryptedName = report.reporterName ? decrypt(report.reporterName) : 'Anonymous';
    const decryptedContact = report.reporterContact ? decrypt(report.reporterContact) : 'Not provided';
    
    const decryptedMessages = (report.messages || []).map(m => {
      return {
        sender: m.sender,
        text: decrypt(m.content.iv + ':' + m.content.content),
        timestamp: m.timestamp
      };
    });

    res.render('admin/reportDetail', {
      title: `Report ${report.ackNumber}`,
      admin: { name: req.session.adminName },
      report,
      decryptedName,
      decryptedContact,
      decryptedMessages,
      csrfToken: req.csrfToken(),
    });
  } catch (err) {
    logger.error('View report error:', err);
    res.render('error', { title: 'Error', message: 'Could not load report.', code: 500 });
  }
};

// POST /admin/reports/:id/status
exports.updateStatus = async (req, res) => {
  try {
    const { status, adminNotes } = req.body;
    const report = await Report.findById(req.params.id);
    if (!report) return res.status(404).json({ error: 'Report not found' });

    const oldStatus = report.status;
    report.status = status;
    report.adminNotes = adminNotes;
    if (status === 'resolved') report.resolvedAt = new Date();
    await report.save();

    await logAction({
      adminId: req.session.adminId,
      adminEmail: req.session.adminEmail,
      action: 'UPDATE_REPORT_STATUS',
      targetType: 'report',
      targetId: report.ackNumber,
      details: `Status changed from ${oldStatus} to ${status}`,
      oldValue: { status: oldStatus },
      newValue: { status },
      ip: req.ip,
    });

    res.redirect(`/admin/reports/${req.params.id}`);
  } catch (err) {
    logger.error('Update status error:', err);
    res.status(500).json({ error: 'Update failed' });
  }
};

// GET /admin/audit-logs
exports.auditLogs = async (req, res) => {
  try {
    const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(100);
    res.render('admin/auditLogs', {
      title: 'Audit Logs',
      admin: { name: req.session.adminName },
      logs,
    });
  } catch (err) {
    res.render('error', { title: 'Error', message: 'Could not load logs.', code: 500 });
  }
};

// POST /admin/message/reply/:id
exports.replyMessage = async (req, res) => {
  const { id } = req.params;
  const { text } = req.body;
  
  if (!text || text.trim().length === 0 || text.length > 2000) {
    return res.redirect(`/admin/reports/${id}`);
  }

  try {
    const report = await Report.findById(id);
    if (!report) return res.redirect('/admin/reports');

    const encryptedText = encrypt(text); // format: "iv:encrypted"
    const [iv, content] = encryptedText.split(':');

    report.messages.push({
      sender: 'admin',
      content: { iv, content },
      timestamp: new Date()
    });

    await report.save();

    await logAction({
      adminId: req.session.adminId,
      adminEmail: req.session.adminEmail,
      action: 'ADMIN_REPLY_MESSAGE',
      targetType: 'report',
      targetId: report.ackNumber,
      details: 'Admin replied to user securely',
      ip: req.ip,
    });
    res.redirect(`/admin/reports/${id}`);
  } catch (err) {
    logger.error('Error sending admin reply:', err);
    res.redirect(`/admin/reports/${id}`);
  }
};
// --- NEW METHOD: BLOCKCHAIN-GATED DOWNLOAD VERIFICATION ---
// GET /admin/reports/:ackNumber/download
exports.downloadSecureFile = async (req, res) => {
  try {
    const { ackNumber } = req.params;

    // 1. Fetch unchangeable parameters directly from the Blockchain ledger
    logger.info(`Fetching blockchain records for file validation. Track ID: ${ackNumber}`);
    const [blockchainCID, blockchainHash] = await contract.getRecord(ackNumber);

    if (!blockchainCID || blockchainCID === "") {
      logger.warn(`File download failed: No secure ledger entry exists for Tracking ID ${ackNumber}`);
      return res.status(404).send("Access Denied: No secure blockchain integrity record exists for this report file.");
    }

    // 2. Fetch the raw asset streaming buffer over decentralized IPFS via your gateway
    const ipfsUrl = `https://pinata.cloud{blockchainCID}`;
    const response = await axios.get(ipfsUrl, { responseType: 'arraybuffer' });
    const downloadedFileBuffer = Buffer.from(response.data);

    // 3. Recalculate local cryptographic hash to confirm no tampering occurred mid-stream
    const currentHash = crypto.createHash('sha256').update(downloadedFileBuffer).digest('hex');

    if (currentHash !== blockchainHash) {
      logger.error(`CRITICAL SECURITY BREACH: Fingerprint mismatch on ID ${ackNumber}. Expected: ${blockchainHash} | Received: ${currentHash}`);

      // Log malicious modification trace to system Audit Log
      await logAction({
        adminId: req.session.adminId,
        adminEmail: req.session.adminEmail,
        action: 'EVIDENCE_TAMPER_ALERT',
        targetType: 'report',
        targetId: ackNumber,
        details: 'CRITICAL ALERT: File integrity mismatch detected on download verification!',
        ip: req.ip,
      });

      return res.status(400).send("SECURITY ALERT: This evidence file has been modified or corrupted on IPFS since its original submission!");
    }

    // 4. Log the validated file viewing to your internal database audit engine for absolute transparency
    await logAction({
      adminId: req.session.adminId,
      adminEmail: req.session.adminEmail,
      action: 'EVIDENCE_SECURE_DOWNLOAD',
      targetType: 'report',
      targetId: ackNumber,
      details: 'Admin verified file credentials on-chain and securely downloaded evidence.',
      ip: req.ip,
    });

    // 5. Securely stream payload down to investigator's browser session
    res.setHeader('Content-Type', response.headers['content-type'] || 'application/octet-stream');
    res.send(downloadedFileBuffer);

  } catch (error) {
    logger.error("Gated asset execution failed:", error);
    res.status(500).send("Secure file retrieval processing failed.");
  }
};



// // controllers/adminController.js
// const Admin = require('../models/Admin');
// const Report = require('../models/Report');
// const AuditLog = require('../models/AuditLog');
// const { encrypt, decrypt } = require('../utils/encryption');
// const { logAction } = require('../services/auditService');
// const logger = require('../utils/logger');

// // GET /admin/login
// exports.showLogin = (req, res) => {
//   res.render('admin/login', {
//     title: 'Admin Login – SecureVoice',
//     csrfToken: req.csrfToken(),
//     error: null,
//   });
// };

// // POST /admin/login
// exports.login = async (req, res) => {
//   const { email, password } = req.body;
//   try {
//     const admin = await Admin.findOne({ email: email?.toLowerCase(), isActive: true });
//     if (!admin || !(await admin.comparePassword(password))) {
//       logger.warn(`Failed admin login attempt for: ${email}`);
//       return res.render('admin/login', {
//         title: 'Admin Login – SecureVoice',
//         csrfToken: req.csrfToken(),
//         error: 'Invalid credentials.',
//       });
//     }

//     admin.lastLogin = new Date();
//     await admin.save();

//     req.session.adminId = admin._id;
//     req.session.adminEmail = admin.email;
//     req.session.adminName = admin.name;
//     req.session.adminRole = admin.role;

//     await logAction({
//       adminId: admin._id,
//       adminEmail: admin.email,
//       action: 'ADMIN_LOGIN',
//       details: 'Admin logged in',
//       ip: req.ip,
//     });

//     logger.info(`Admin login: ${admin.email}`);
//     res.redirect('/admin/dashboard');
//   } catch (err) {
//     logger.error('Admin login error:', err);
//     res.render('admin/login', {
//       title: 'Admin Login – SecureVoice',
//       csrfToken: req.csrfToken(),
//       error: 'Server error. Try again.',
//     });
//   }
// };

// // POST /admin/logout
// exports.logout = async (req, res) => {
//   await logAction({
//     adminId: req.session.adminId,
//     adminEmail: req.session.adminEmail,
//     action: 'ADMIN_LOGOUT',
//     ip: req.ip,
//   });
//   req.session.destroy();
//   res.redirect('/admin/login');
// };

// // GET /admin/dashboard
// exports.dashboard = async (req, res) => {
//   try {
//     const [
//       totalReports,
//       pendingReports,
//       highRiskCount,
//       criticalRiskCount,
//       suspiciousCount,
//       recentReports,
//       recentAuditLogs,
//       categoryStats,
//       statusStats,
//     ] = await Promise.all([
//       Report.countDocuments(),
//       Report.countDocuments({ status: 'pending' }),
//       Report.countDocuments({ 'riskScore.level': 'high' }),
//       Report.countDocuments({ 'riskScore.level': 'critical' }),
//       Report.countDocuments({ 'threatFlags.suspicionScore': { $gte: 50 } }),
//       Report.find().sort({ submittedAt: -1 }).limit(8).select('ackNumber title category severity riskScore status submittedAt threatFlags'),
//       AuditLog.find().sort({ timestamp: -1 }).limit(10),
//       Report.aggregate([{ $group: { _id: '$category', count: { $sum: 1 } } }]),
//       Report.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }]),
//     ]);

//     res.render('admin/dashboard', {
//       title: 'Security Dashboard – SecureVoice',
//       admin: { name: req.session.adminName, role: req.session.adminRole },
//       stats: {
//         totalReports,
//         pendingReports,
//         highRiskCount,
//         criticalRiskCount,
//         suspiciousCount,
//         resolvedReports: (statusStats.find(s => s._id === 'resolved') || {}).count || 0,
//       },
//       recentReports,
//       recentAuditLogs,
//       categoryStats,
//       statusStats,
//     });
//   } catch (err) {
//     logger.error('Dashboard error:', err);
//     res.render('error', { title: 'Error', message: 'Dashboard load failed.', code: 500 });
//   }
// };

// // GET /admin/reports
// exports.listReports = async (req, res) => {
//   try {
//     const page = parseInt(req.query.page) || 1;
//     const limit = 15;
//     const skip = (page - 1) * limit;

//     const filter = {};
//     if (req.query.status) filter.status = req.query.status;
//     if (req.query.risk) filter['riskScore.level'] = req.query.risk;
//     if (req.query.category) filter.category = req.query.category;

//     const [reports, total] = await Promise.all([
//       Report.find(filter).sort({ submittedAt: -1 }).skip(skip).limit(limit),
//       Report.countDocuments(filter),
//     ]);

//     res.render('admin/reports', {
//       title: 'All Reports',
//       admin: { name: req.session.adminName },
//       reports,
//       currentPage: page,
//       totalPages: Math.ceil(total / limit),
//       total,
//       query: req.query,
//     });
//   } catch (err) {
//     logger.error('List reports error:', err);
//     res.render('error', { title: 'Error', message: 'Could not load reports.', code: 500 });
//   }
// };

// // GET /admin/reports/:id
// exports.viewReport = async (req, res) => {
//   try {
//     const report = await Report.findById(req.params.id);
//     if (!report) return res.render('error', { title: '404', message: 'Report not found.', code: 404 });

//     // Decrypt sensitive fields for admin view
//     const decryptedName = report.reporterName ? decrypt(report.reporterName) : 'Anonymous';
//     const decryptedContact = report.reporterContact ? decrypt(report.reporterContact) : 'Not provided';
    
//     const decryptedMessages = (report.messages || []).map(m => {
//       return {
//         sender: m.sender,
//         text: decrypt(m.content.iv + ':' + m.content.content),
//         timestamp: m.timestamp
//       };
//     });

//     res.render('admin/reportDetail', {
//       title: `Report ${report.ackNumber}`,
//       admin: { name: req.session.adminName },
//       report,
//       decryptedName,
//       decryptedContact,
//       decryptedMessages,
//       csrfToken: req.csrfToken(),
//     });
//   } catch (err) {
//     logger.error('View report error:', err);
//     res.render('error', { title: 'Error', message: 'Could not load report.', code: 500 });
//   }
// };

// // POST /admin/reports/:id/status
// exports.updateStatus = async (req, res) => {
//   try {
//     const { status, adminNotes } = req.body;
//     const report = await Report.findById(req.params.id);
//     if (!report) return res.status(404).json({ error: 'Report not found' });

//     const oldStatus = report.status;
//     report.status = status;
//     report.adminNotes = adminNotes;
//     if (status === 'resolved') report.resolvedAt = new Date();
//     await report.save();

//     await logAction({
//       adminId: req.session.adminId,
//       adminEmail: req.session.adminEmail,
//       action: 'UPDATE_REPORT_STATUS',
//       targetType: 'report',
//       targetId: report.ackNumber,
//       details: `Status changed from ${oldStatus} to ${status}`,
//       oldValue: { status: oldStatus },
//       newValue: { status },
//       ip: req.ip,
//     });

//     res.redirect(`/admin/reports/${req.params.id}`);
//   } catch (err) {
//     logger.error('Update status error:', err);
//     res.status(500).json({ error: 'Update failed' });
//   }
// };

// // GET /admin/audit-logs
// exports.auditLogs = async (req, res) => {
//   try {
//     const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(100);
//     res.render('admin/auditLogs', {
//       title: 'Audit Logs',
//       admin: { name: req.session.adminName },
//       logs,
//     });
//   } catch (err) {
//     res.render('error', { title: 'Error', message: 'Could not load logs.', code: 500 });
//   }
// };

// // POST /admin/message/reply/:id
// exports.replyMessage = async (req, res) => {
//   const { id } = req.params;
//   const { text } = req.body;
  
//   if (!text || text.trim().length === 0 || text.length > 2000) {
//     return res.redirect(`/admin/reports/${id}`);
//   }

//   try {
//     const report = await Report.findById(id);
//     if (!report) return res.redirect('/admin/reports');

//     const encryptedText = encrypt(text); // format: "iv:encrypted"
//     const [iv, content] = encryptedText.split(':');

//     report.messages.push({
//       sender: 'admin',
//       content: { iv, content },
//       timestamp: new Date()
//     });

//     await report.save();

//     await logAction({
//       adminId: req.session.adminId,
//       adminEmail: req.session.adminEmail,
//       action: 'ADMIN_REPLY_MESSAGE',
//       targetType: 'report',
//       targetId: report.ackNumber,
//       details: 'Admin replied to user securely',
//       ip: req.ip,
//     });

//     res.redirect(`/admin/reports/${id}`);
//   } catch (err) {
//     logger.error('Error sending admin reply:', err);
//     res.redirect(`/admin/reports/${id}`);
//   }
// };

// GET /admin/audio/:filename
exports.serveAudio = async (req, res) => {
  const { filename } = req.params;
  const fs = require('fs');
  const path = require('path');
  
  const filePath = path.join(process.cwd(), 'uploads', filename);
  
  // Basic path traversal prevention
  if (!filePath.startsWith(path.join(process.cwd(), 'uploads'))) {
    return res.status(403).send('Forbidden');
  }

  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.status(404).send('Audio file not found');
  }
};
