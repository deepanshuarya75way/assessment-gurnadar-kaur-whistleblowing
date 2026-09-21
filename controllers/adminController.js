// controllers/adminController.js
const Admin = require('../models/Admin');
const Report = require('../models/Report');
const AuditLog = require('../models/AuditLog');
const { encrypt, decrypt } = require('../utils/encryption');
const { logAction } = require('../services/auditService');
const logger = require('../utils/logger');

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

// GET /admin/dashboard5
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
//       statusStats,  // 1. Fetch the raw counts array 
//       clusterGroupsData,
//       // 2. Fetch the reports belonging to clusters to populate the bottom click list
//       clusteredReports
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
      // ADDED EXTENDED DESTRUCTURING RECIPIENT KEYS
      clusterGroupsData,
      clusteredReports
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
      // ADDED MISSING QUERIES IN PROMISE STACK
      Report.aggregate([
        { $match: { clusterId: { $ne: null } } },
        { $group: { _id: "$clusterId" } },
        { $count: "count" }
      ]),
      Report.find({ clusterId: { $ne: null } }).sort({ submittedAt: -1 }).select('ackNumber title category status clusterId submittedAt')
    ]);

    // Secure array lookup calculations to fetch the matching number count
    const clusterGroupsCount = clusterGroupsData && clusterGroupsData[0] ? clusterGroupsData[0].count : 0;

    res.render('admin/dashboard', {
      title: 'Security Dashboard – SecureVoice',
      admin: { name: req.session.adminName, role: req.session.adminRole },
      stats: {
        totalReports,
        pendingReports,
        highRiskCount,
        criticalRiskCount,
        suspiciousCount,
        clusterGroupsCount, // <-- Now perfectly mapped to your custom view template variable
        resolvedReports: (statusStats.find(s => s._id === 'resolved') || {}).count || 0,
      },
      recentReports,
      clusteredReports, // <-- Passed completely to populate your new click sections!
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

    // 1. Fetch matching documents while filtering out permanently dismissed items
    const baseDismissed = report.dismissedMatches || [];
    const similarReports = await Report.find({
      $text: { $search: report.description },
      _id: { $ne: report._id, $nin: baseDismissed }, // Excludes itself and all items inside dismissedMatches
      category: report.category, 
      accusedOrganization: report.accusedOrganization 
    })
    .select({ score: { $meta: "textScore" }, ackNumber: 1, title: 1, clusterId: 1, status: 1, accusedPersons: 1 })
    .sort({ score: { $meta: "textScore" } })
    .limit(5);

    // 2. Generate custom structured reason tags for UI explanations
    const similarWithReasons = similarReports.map(function(match) {
      const doc = match._doc || match;
      // Normalizes standard textScore metrics into an understandable percentage frame
      const textScorePercent = Math.min(100, Math.round((doc.score || 1) * 85));
      const reasons = ["Vocabulary patterns overlap: " + textScorePercent + "%"];
      
      const overlappingNames = (doc.accusedPersons || []).filter(function(name) {
        return (report.accusedPersons || []).includes(name);
      });
      
      if (overlappingNames.length > 0) {
        reasons.push("Identical target subjects: " + overlappingNames.join(', '));
      }
      
      doc.matchReasons = reasons;
      return doc;
    });

    // 3. Query historical merge trails connected to this specific acknowledgment identity code
    let mergeHistory = [];
    try {
      const AuditLog = mongoose.model('AuditLog');
      mergeHistory = await AuditLog.find({
        action: 'LINK_REPORT_CLUSTER',
        $or: [
          { targetId: report.ackNumber },
          { details: { $regex: report.ackNumber } }
        ]
      }).sort({ timestamp: -1 });
    } catch (auditError) {
      logger.warn('AuditLog model could not be queried for timeline logs: ' + auditError.message);
    }

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
      title: 'Report ' + report.ackNumber,
      admin: { name: req.session.adminName },
      report: report,
      similarReports: similarWithReasons, // <-- Passes upgraded version containing matching explanations
      mergeHistory: mergeHistory,         // <-- Passes link log tracking collections
      decryptedName: decryptedName,
      decryptedContact: decryptedContact,
      decryptedMessages: decryptedMessages,
      csrfToken: req.csrfToken()
    });
  } catch (err) {
    logger.error('View report error:', err);
    res.render('error', { title: 'Error', message: 'Could not load report.', code: 500 });
  }
};

// exports.viewReport = async (req, res) => {
//   try {
//     const report = await Report.findById(req.params.id);
//     if (!report) return res.render('error', { title: '404', message: 'Report not found.', code: 404 });

//         // =========================================================================
//     // FIXED: CORRECT MONGODB TEXT SEARCH SYNTAX
//     // =========================================================================
//     const similarReports = await Report.find({
//       $text: { $search: report.description },
//       _id: { $ne: report._id }, // Exclude current report
//       category: report.category, // Limits text scan to matches within the same enum category
//       accusedOrganization: report.accusedOrganization // Limits matches to the same target entity
//     })
//     .select({ score: { $meta: "textScore" }, ackNumber: 1, title: 1, clusterId: 1, status: 1 })
//     .sort({ score: { $meta: "textScore" } })
//     .limit(5);
//     // =========================================================================

//     // =========================================================================

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
//       similarReports, // <-- Passed directly to admin/reportDetail.ejs
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


// POST /admin/reports/:id/status
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

    // =========================================================================
    // DYNAMIC SYNC: AUTOMATICALLY UPDATE ALL OTHER LINKED COMPLAINTS IN CLUSTER
    // =========================================================================
    if (report.clusterId) {
      const clusterUpdateData = { status: status, adminNotes: adminNotes };
      if (status === 'resolved') {
        clusterUpdateData.resolvedAt = new Date();
      }
      
      // Update all documents sharing this clusterId except the current file itself
      await Report.updateMany(
        { clusterId: report.clusterId, _id: { $ne: report._id } },
        { $set: clusterUpdateData }
      );
    }
    // =========================================================================

    await logAction({
      adminId: req.session.adminId,
      adminEmail: req.session.adminEmail,
      action: 'UPDATE_REPORT_STATUS',
      targetType: 'report',
      targetId: report.ackNumber,
      details: 'Status changed from ' + oldStatus + ' to ' + status + ' (Synced to cluster group)',
      oldValue: { status: oldStatus },
      newValue: { status },
      ip: req.ip,
    });

    res.redirect('/admin/reports/' + req.params.id);
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


// POST /admin/reports/:id/link
exports.linkReportToCluster = async (req, res) => {
  try {
    const { targetClusterId } = req.body;
    const report = await Report.findById(req.params.id);
    if (!report) return res.status(404).json({ error: 'Report not found' });

    // Generate a new cluster ID if starting a clean cluster group, otherwise join the target cluster
    const finalClusterId = targetClusterId || new mongoose.Types.ObjectId();

    report.clusterId = finalClusterId;
    report.threatFlags.isDuplicate = true; // Flips your existing schema flag
    await report.save();

    await logAction({
      adminId: req.session.adminId,
      adminEmail: req.session.adminEmail,
      action: 'LINK_REPORT_CLUSTER',
      targetType: 'report',
      targetId: report.ackNumber,
      details: `Report linked into Case Cluster: ${finalClusterId}`,
      ip: req.ip,
    });

    res.redirect(`/admin/reports/${req.params.id}`);
  } catch (err) {
    logger.error('Link cluster error:', err);
    res.status(500).json({ error: 'Failed to link reports together.' });
  }
};






// GET /admin/dashboard
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
//       // ==========================================
//       // NEW: Count distinct linked report groups
//       // ==========================================
//       clusterGroupsCount 
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
//       // ==========================================
//       // NEW AGGREGATION BLOCK
//       // ==========================================
//       Report.aggregate([
//         { $match: { clusterId: { $ne: null } } },
//         { $group: { _id: "$clusterId" } },
//         { $count: "count" }
//       ]).then(res => res[0]?.count || 0)
//       // ==========================================
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
//         clusterGroupsCount, 
//         resolvedReports: (statusStats.find(s => s._id === 'resolved') || {}).count || 0,
//       },
//       recentReports,
//       recentAuditLogs,
//       categoryStats,
//       statusStats
//     }); // <--- FIXED: Changed from ] to }
//   } catch (err) {
//     logger.error('Dashboard error:', err);
//     res.render('error', { title: 'Error', message: 'Dashboard load failed.', code: 500 });
//   }
// };



// GET /admin/reports/:id
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
