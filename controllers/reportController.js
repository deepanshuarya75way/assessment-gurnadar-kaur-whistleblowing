const { validationResult } = require('express-validator');
const Report = require('../models/Report');
const { encrypt, decrypt, hashSHA256, hashReport } = require('../utils/encryption');
const { generateAckNumber } = require('../utils/tokenGenerator');
const { analyzeReport } = require('../services/threatDetection');
const { calculateRiskScore } = require('../services/riskScoring');
const logger = require('../utils/logger');

// IMPORT THE BLOCKCHAIN/IPFS UTILITY HERE
const { secureUpload } = require('../utils/blockchain');

// GET /report/submit — show form
exports.showSubmitForm = (req, res) => {
  res.render('report/submit', {
    title: 'Submit Anonymous Report',
    csrfToken: req.csrfToken(),
    errors: [],
    formData: {},
  });
};

// POST /report/submit — handle submission
exports.submitReport = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('report/submit', {
      title: 'Submit Anonymous Report',
      csrfToken: req.csrfToken(),
      errors: errors.array(),
      formData: req.body,
    });
  }

  try {
    const {
      reporterName, reporterContact, title, description,
      category, severity, accusedOrganization, accusedPersons, location,
    } = req.body;

    // Hash the IP — never store raw IP
    const rawIp = req.ip || req.connection.remoteAddress || 'unknown';
    const ipHash = hashSHA256(rawIp, process.env.IP_SALT);

    // Threat detection
    const threat = await analyzeReport({ title, description, category }, ipHash);

    // Generate the unique acknowledgement number early so we can attach it to the blockchain record
    const ackNumber = generateAckNumber();

    // ─── NEW MODIFIED BLOCKCHAIN & IPFS STORAGE IMPLEMENTATION ───
    let evidenceFiles = [];
    if (req.files && req.files['evidence']) {
      let fileIndex = 0;
      for (const f of req.files['evidence']) {
        logger.info(`Uploading evidence file ${f.originalname} to IPFS for tracking ID: ${ackNumber}`);
        
        // Append index suffix to prevent multiple files from overwriting each other on the contract ledger
        const compositeKey = `${ackNumber}-file-${fileIndex}`;
        const ipfsResult = await secureUpload(compositeKey, f.buffer, f.originalname);
        
        evidenceFiles.push({
          originalName: f.originalname,
          mimeType: f.mimetype,
          size: f.size,
          ipfsCID: ipfsResult.ipfsCID,     // Saved from Pinata response
          fileHash: ipfsResult.fileHash    // Saved from Blockchain fingerprint
        });
        fileIndex++;
      }
    }
    
    let audioEvidence = [];
    if (req.files && req.files['audioEvidence'] && req.files['audioEvidence'].length > 0) {
      const audioFile = req.files['audioEvidence'][0];
      logger.info(`Uploading audio file ${audioFile.originalname} to IPFS for tracking ID: ${ackNumber}`);
      
      const compositeAudioKey = `${ackNumber}-audio-0`;
      const ipfsResult = await secureUpload(compositeAudioKey, audioFile.buffer, audioFile.originalname);
      
      audioEvidence.push({
        filePath: `ipfs://${ipfsResult.ipfsCID}`,
        originalName: audioFile.originalname,
        mimeType: audioFile.mimetype,
        size: audioFile.size,
        ipfsCID: ipfsResult.ipfsCID,       // Saved from Pinata response
        fileHash: ipfsResult.fileHash,     // Saved from Blockchain fingerprint
        uploadedAt: new Date()
      });
    }
    // ─────────────────────────────────────────────────────────────

    const parsedAccused = accusedPersons
      ? accusedPersons.split(',').map(s => s.trim()).filter(Boolean)
      : [];

    const riskScore = calculateRiskScore({
      severity, category, description,
      evidenceFiles,
      accusedPersons: parsedAccused,
    });

    // Get last report for hash chaining
    const lastReport = await Report.findOne().sort({ submittedAt: -1 }).select('contentHash');
    const previousHash = lastReport ? lastReport.contentHash : '0';

    // Generate content hash
    const contentHash = hashReport({ title, description, category, accusedOrganization });

    // Build report object
    const report = new Report({
      ackNumber,
      reporterName: reporterName ? encrypt(reporterName) : null,
      reporterContact: reporterContact ? encrypt(reporterContact) : null,
      title,
      description,
      category,
      severity,
      accusedOrganization,
      accusedPersons: parsedAccused,
      location,
      evidenceFiles, 
      audioEvidence, 
      ipHash,
      userAgent: req.headers['user-agent']?.substring(0, 200),
      riskScore,
      threatFlags: {
        isDuplicate: threat.isDuplicate,
        isSpam: threat.isSpam,
        suspicionScore: threat.suspicionScore,
        flags: threat.flags,
      },
      contentHash,
      previousHash,
      status: 'pending',
    });

    await report.save();
    logger.info(`New report submitted: ${ackNumber} | Risk: ${riskScore.level}`);

    // Redirect to confirmation page
    res.redirect(`/report/confirmation/${ackNumber}`);

  } catch (err) {
    logger.error('Report submission error:', err);
    res.render('report/submit', {
      title: 'Submit Anonymous Report',
      csrfToken: req.csrfToken(),
      errors: [{ msg: 'Submission failed. Please try again.' }],
      formData: req.body,
    });
  }
};

// GET /report/confirmation/:ackNumber
exports.showConfirmation = async (req, res) => {
  try {
    const { ackNumber } = req.params;
    const report = await Report.findOne({ ackNumber }).select('ackNumber submittedAt status category severity');
    if (!report) {
      return res.render('error', { title: 'Not Found', message: 'Report not found.', code: 404 });
    }
    res.render('report/confirmation', {
      title: 'Report Submitted',
      report,
    });
  } catch (err) {
    logger.error('Error opening confirmation page:', err);
    res.status(500).send("Internal server error.");
  }
};

// GET /report/track — show tracking form
exports.showTrackForm = (req, res) => {
  res.render('report/track', {
    title: 'Track Your Report',
    csrfToken: req.csrfToken(),
    result: null,
    error: null,
  });
};

exports.trackReport = async (req, res) => {
  const { ackNumber } = req.body;
  const report = await Report.findOne({ ackNumber: ackNumber?.trim() })
    .select('ackNumber submittedAt status category severity updatedAt');

  if (!report) {
    return res.render('report/track', {
      title: 'Track Your Report',
      csrfToken: req.csrfToken(),
      result: null,
      error: 'No report found with that acknowledgement number.',
    });
  }

  res.render('report/track', {
    title: 'Track Your Report',
    csrfToken: req.csrfToken(),
    result: report,
    error: null,
  });
};

exports.sendMessage = async (req, res) => {
  const { trackingId, text } = req.body;
  if (!trackingId || !text || text.trim().length === 0 || text.length > 2000) {
    return res.status(400).json({ error: 'Invalid input' });
  }

  try {
    const report = await Report.findOne({ ackNumber: trackingId });
    if (!report) return res.status(404).json({ error: 'Report not found' });
    const encryptedText = encrypt(text); 
    const [iv, content] = encryptedText.split(':');

    report.messages.push({
      sender: 'user',
      content: { iv, content },
      timestamp: new Date()
    });

    await report.save();
    res.json({ success: true, message: 'Message securely sent.' });
  } catch (err) {
    logger.error('Error sending message:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

exports.getMessages = async (req, res) => {
  const { trackingId } = req.params;
  try {
    const report = await Report.findOne({ ackNumber: trackingId }).select('messages');
    if (!report) return res.status(404).json({ error: 'Report not found' });

    const decryptedMessages = report.messages.map(m => {
      const encryptedStr = m.content.iv + ':' + m.content.content;
      return {
        id: m._id,
        sender: m.sender,
        text: decrypt(encryptedStr),
        timestamp: m.timestamp
      };
    });
    res.json({ messages: decryptedMessages });
  } catch (err) {
    logger.error('Error fetching messages:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};





// GET /report/confirmation/:ackNumber
exports.showConfirmation = async (req, res) => {
  const { ackNumber } = req.params;
  const report = await Report.findOne({ ackNumber }).select('ackNumber submittedAt status category severity');
  if (!report) {
    return res.render('error', { title: 'Not Found', message: 'Report not found.', code: 404 });
  }
  res.render('report/confirmation', {
    title: 'Report Submitted',
    report,
  });
};

// GET /report/track — show tracking form
exports.showTrackForm = (req, res) => {
  res.render('report/track', {
    title: 'Track Your Report',
    csrfToken: req.csrfToken(),
    result: null,
    error: null,
  });
};

// POST /report/track — look up report by ack number
exports.trackReport = async (req, res) => {
  const { ackNumber } = req.body;
  const report = await Report.findOne({ ackNumber: ackNumber?.trim() })
    .select('ackNumber submittedAt status category severity updatedAt');

  if (!report) {
    return res.render('report/track', {
      title: 'Track Your Report',
      csrfToken: req.csrfToken(),
      result: null,
      error: 'No report found with that acknowledgement number.',
    });
  }

  res.render('report/track', {
    title: 'Track Your Report',
    csrfToken: req.csrfToken(),
    result: report,
    error: null,
  });
};

// --- Secure Dead Drop Messaging (User) ---
exports.sendMessage = async (req, res) => {
  const { trackingId, text } = req.body;
  if (!trackingId || !text || text.trim().length === 0 || text.length > 2000) {
    return res.status(400).json({ error: 'Invalid input' });
  }

  try {
    const report = await Report.findOne({ ackNumber: trackingId });
    if (!report) return res.status(404).json({ error: 'Report not found' });

    // Encrypt message
    const encryptedText = encrypt(text); // format: "iv:encrypted"
    const [iv, content] = encryptedText.split(':');

    report.messages.push({
      sender: 'user',
      content: { iv, content },
      timestamp: new Date()
    });

    await report.save();
    res.json({ success: true, message: 'Message securely sent.' });
  } catch (err) {
    logger.error('Error sending message:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};

exports.getMessages = async (req, res) => {
  const { trackingId } = req.params;
  try {
    const report = await Report.findOne({ ackNumber: trackingId }).select('messages');
    if (!report) return res.status(404).json({ error: 'Report not found' });

    const decryptedMessages = report.messages.map(m => {
      const encryptedStr = m.content.iv + ':' + m.content.content;
      return {
        id: m._id,
        sender: m.sender,
        text: decrypt(encryptedStr),
        timestamp: m.timestamp
      };
    });

    res.json({ messages: decryptedMessages });
  } catch (err) {
    logger.error('Error fetching messages:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};


// // controllers/reportController.js
// const { validationResult } = require('express-validator');
// const Report = require('../models/Report');
// const { encrypt, decrypt, hashSHA256, hashReport } = require('../utils/encryption');
// const { generateAckNumber } = require('../utils/tokenGenerator');
// const { analyzeReport } = require('../services/threatDetection');
// const { calculateRiskScore } = require('../services/riskScoring');
// const logger = require('../utils/logger');

// // GET /report/submit — show form
// exports.showSubmitForm = (req, res) => {
//   res.render('report/submit', {
//     title: 'Submit Anonymous Report',
//     csrfToken: req.csrfToken(),
//     errors: [],
//     formData: {},
//   });
// };

// // POST /report/submit — handle submission
// exports.submitReport = async (req, res) => {
//   const errors = validationResult(req);
//   if (!errors.isEmpty()) {
//     return res.render('report/submit', {
//       title: 'Submit Anonymous Report',
//       csrfToken: req.csrfToken(),
//       errors: errors.array(),
//       formData: req.body,
//     });
//   }

//   try {
//     const {
//       reporterName, reporterContact, title, description,
//       category, severity, accusedOrganization, accusedPersons, location,
//     } = req.body;

//     // Hash the IP — never store raw IP
//     const rawIp = req.ip || req.connection.remoteAddress || 'unknown';
//     const ipHash = hashSHA256(rawIp, process.env.IP_SALT);

//     // Threat detection
//     const threat = await analyzeReport({ title, description, category }, ipHash);

//     // Risk scoring
//     const evidenceFiles = (req.files && req.files['evidence'] ? req.files['evidence'] : []).map(f => ({
//       originalName: f.originalname,
//       storedName: f.filename,
//       mimeType: f.mimetype,
//       size: f.size,
//     }));
    
//     let audioEvidence = [];
//     if (req.files && req.files['audioEvidence'] && req.files['audioEvidence'].length > 0) {
//       audioEvidence.push({
//         filePath: req.files['audioEvidence'][0].filename,
//         uploadedAt: new Date()
//       });
//     }

//     const parsedAccused = accusedPersons
//       ? accusedPersons.split(',').map(s => s.trim()).filter(Boolean)
//       : [];

//     const riskScore = calculateRiskScore({
//       severity, category, description,
//       evidenceFiles,
//       accusedPersons: parsedAccused,
//     });

//     // Get last report for hash chaining
//     const lastReport = await Report.findOne().sort({ submittedAt: -1 }).select('contentHash');
//     const previousHash = lastReport ? lastReport.contentHash : '0';

//     // Generate ack number and content hash
//     const ackNumber = generateAckNumber();
//     const contentHash = hashReport({ title, description, category, accusedOrganization });

//     // Build report object
//     const report = new Report({
//       ackNumber,
//       reporterName: reporterName ? encrypt(reporterName) : null,
//       reporterContact: reporterContact ? encrypt(reporterContact) : null,
//       title,
//       description,
//       category,
//       severity,
//       accusedOrganization,
//       accusedPersons: parsedAccused,
//       location,
//       evidenceFiles,
//       audioEvidence,
//       ipHash,
//       userAgent: req.headers['user-agent']?.substring(0, 200),
//       riskScore,
//       threatFlags: {
//         isDuplicate: threat.isDuplicate,
//         isSpam: threat.isSpam,
//         suspicionScore: threat.suspicionScore,
//         flags: threat.flags,
//       },
//       contentHash,
//       previousHash,
//       status: 'pending',
//     });

//     await report.save();
//     logger.info(`New report submitted: ${ackNumber} | Risk: ${riskScore.level}`);

//     // Redirect to confirmation page
//     res.redirect(`/report/confirmation/${ackNumber}`);

//   } catch (err) {
//     logger.error('Report submission error:', err);
//     res.render('report/submit', {
//       title: 'Submit Anonymous Report',
//       csrfToken: req.csrfToken(),
//       errors: [{ msg: 'Submission failed. Please try again.' }],
//       formData: req.body,
//     });
//   }
// };

// // GET /report/confirmation/:ackNumber
// exports.showConfirmation = async (req, res) => {
//   const { ackNumber } = req.params;
//   const report = await Report.findOne({ ackNumber }).select('ackNumber submittedAt status category severity');
//   if (!report) {
//     return res.render('error', { title: 'Not Found', message: 'Report not found.', code: 404 });
//   }
//   res.render('report/confirmation', {
//     title: 'Report Submitted',
//     report,
//   });
// };

// // GET /report/track — show tracking form
// exports.showTrackForm = (req, res) => {
//   res.render('report/track', {
//     title: 'Track Your Report',
//     csrfToken: req.csrfToken(),
//     result: null,
//     error: null,
//   });
// };

// // POST /report/track — look up report by ack number
// exports.trackReport = async (req, res) => {
//   const { ackNumber } = req.body;
//   const report = await Report.findOne({ ackNumber: ackNumber?.trim() })
//     .select('ackNumber submittedAt status category severity updatedAt');

//   if (!report) {
//     return res.render('report/track', {
//       title: 'Track Your Report',
//       csrfToken: req.csrfToken(),
//       result: null,
//       error: 'No report found with that acknowledgement number.',
//     });
//   }

//   res.render('report/track', {
//     title: 'Track Your Report',
//     csrfToken: req.csrfToken(),
//     result: report,
//     error: null,
//   });
// };

// // --- Secure Dead Drop Messaging (User) ---
// exports.sendMessage = async (req, res) => {
//   const { trackingId, text } = req.body;
//   if (!trackingId || !text || text.trim().length === 0 || text.length > 2000) {
//     return res.status(400).json({ error: 'Invalid input' });
//   }

//   try {
//     const report = await Report.findOne({ ackNumber: trackingId });
//     if (!report) return res.status(404).json({ error: 'Report not found' });

//     // Encrypt message
//     const encryptedText = encrypt(text); // format: "iv:encrypted"
//     const [iv, content] = encryptedText.split(':');

//     report.messages.push({
//       sender: 'user',
//       content: { iv, content },
//       timestamp: new Date()
//     });

//     await report.save();
//     res.json({ success: true, message: 'Message securely sent.' });
//   } catch (err) {
//     logger.error('Error sending message:', err);
//     res.status(500).json({ error: 'Internal server error' });
//   }
// };

// exports.getMessages = async (req, res) => {
//   const { trackingId } = req.params;
//   try {
//     const report = await Report.findOne({ ackNumber: trackingId }).select('messages');
//     if (!report) return res.status(404).json({ error: 'Report not found' });

//     const decryptedMessages = report.messages.map(m => {
//       const encryptedStr = m.content.iv + ':' + m.content.content;
//       return {
//         id: m._id,
//         sender: m.sender,
//         text: decrypt(encryptedStr),
//         timestamp: m.timestamp
//       };
//     });

//     res.json({ messages: decryptedMessages });
//   } catch (err) {
//     logger.error('Error fetching messages:', err);
//     res.status(500).json({ error: 'Internal server error' });
//   }
// };
