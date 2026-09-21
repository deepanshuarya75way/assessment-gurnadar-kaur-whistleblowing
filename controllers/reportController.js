// controllers/reportController.js

const { validationResult } = require('express-validator');
const Report = require('../models/Report');
const mongoose = require('mongoose'); // Required for unique ID assignment 
const { encrypt, decrypt, hashSHA256, hashReport } = require('../utils/encryption');
const { generateAckNumber } = require('../utils/tokenGenerator');
const { analyzeReport } = require('../services/threatDetection');
const { calculateRiskScore } = require('../services/riskScoring');
const logger = require('../utils/logger');

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

    // Risk scoring
    const evidenceFiles = (req.files && req.files['evidence'] ? req.files['evidence'] : []).map(f => ({
      originalName: f.originalname,
      storedName: f.filename,
      mimeType: f.mimetype,
      size: f.size,
    }));
    
    let audioEvidence = [];
    if (req.files && req.files['audioEvidence'] && req.files['audioEvidence'].length > 0) {
      audioEvidence.push({
        filePath: req.files['audioEvidence'][0].filename,
        uploadedAt: new Date()
      });
    }

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

    // Generate ack number and content hash
    const ackNumber = generateAckNumber();
    const contentHash = hashReport({ title, description, category, accusedOrganization });

    // Initialize custom variables for duplicate auto-clustering
    let assignedClusterId = null;
    let finalIsDuplicate = threat.isDuplicate;
    let finalSuspicionScore = threat.suspicionScore;
    let finalFlags = [...(threat.flags || [])];

    // =========================================================================
    // AUTOMATED THREAT DETECTION: PROACTIVE DUPLICATE SCANNER (FIXED)
    // =========================================================================
     try {
      // 1. Fixed operators ($text, $search) and 2. Removed the broken backslash escape from $meta
      const matchingIncident = await Report.findOne({
        $text: { $search: description },
        category: category,
        accusedOrganization: accusedOrganization
      })
      .select({ score: { $meta: "textScore" }, clusterId: 1 });

      if (matchingIncident) {
        finalIsDuplicate = true;
        finalSuspicionScore = Math.max(75, threat.suspicionScore);
        if (!finalFlags.includes('AUTOMATED_TEXT_MATCH_CLUSTER')) {
          finalFlags.push('AUTOMATED_TEXT_MATCH_CLUSTER');
        }

        if (matchingIncident.clusterId) {
          assignedClusterId = matchingIncident.clusterId;
        } else {
          const sharedClusterId = new mongoose.Types.ObjectId();
          assignedClusterId = sharedClusterId;
          
          await Report.findByIdAndUpdate(matchingIncident._id, { clusterId: sharedClusterId });
        }
      }
    } catch (scanError) {
      logger.error("Proactive duplicate scan bypassed:", scanError);
    }
    // =========================================================================

    // =========================================================================

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
        isDuplicate: finalIsDuplicate,
        isSpam: threat.isSpam,
        suspicionScore: finalSuspicionScore,
        flags: finalFlags,
      },
      clusterId: assignedClusterId,
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
    logger.error('Confirmation page load error:', err);
    res.render('error', { title: 'Error', message: 'Could not load confirmation details.', code: 500 });
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

// POST /report/track — look up report by ack number
exports.trackReport = async (req, res) => {
  try {
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
  } catch (err) {
    logger.error('Track report error:', err);
    res.render('error', { title: 'Error', message: 'Could not find tracking logs.', code: 500 });
  }
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
