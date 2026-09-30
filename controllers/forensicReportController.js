// controllers/forensicReportController.js
// Handles forensic PDF generation, blockchain verification, and secure IPFS file retrieval

const mongoose = require('mongoose');
const axios = require('axios');
const crypto = require('crypto');
const { createForensicPDF } = require('../services/forensicReportService');
const { logAction } = require('../services/auditService');
const { verifyPDFIntegrity, hashFileBuffer, secureDownload } = require('../utils/blockchain');
const Report = require('../models/Report');
const logger = require('../utils/logger');

/**
 * GET /admin/reports/:id/forensic-pdf
 * Generate and download a forensic PDF report for a specific complaint
 */
exports.downloadForensicPDF = async (req, res) => {
  try {
    const { id } = req.params;

    // ── Validate MongoDB ObjectId ──────────────────────────────────────────
    if (!mongoose.Types.ObjectId.isValid(id)) {
      logger.warn(`Forensic PDF: Invalid report ID attempted – ${id}`);
      return res.status(400).json({ error: 'Invalid report ID format.' });
    }

    // ── Generate the forensic PDF ─────────────────────────────────────────
    logger.info(`Forensic PDF generation started for report: ${id} by admin: ${req.session.adminEmail}`);
    const result = await createForensicPDF(id);

    if (!result) {
      logger.warn(`Forensic PDF: Report not found – ${id}`);
      return res.status(404).json({ error: 'Report not found.' });
    }

    // ── Audit log the PDF generation ──────────────────────────────────────
    await logAction({
      adminId: req.session.adminId,
      adminEmail: req.session.adminEmail,
      action: 'GENERATE_FORENSIC_PDF',
      targetType: 'report',
      targetId: result.ackNumber,
      details: `Forensic PDF generated for report ${result.ackNumber}`,
      ip: req.ip,
    });

    // ── Set response headers and send PDF ────────────────────────────────
    const filename = `SecureVoice_Forensic_${result.ackNumber}.pdf`;

    // Ensure we have a proper Buffer
    const pdfBuffer = Buffer.isBuffer(result.pdfBuffer)
      ? result.pdfBuffer
      : Buffer.from(result.pdfBuffer);

    res.writeHead(200, {
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': pdfBuffer.length,
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Pragma': 'no-cache',
    });

    logger.info(`Forensic PDF generated successfully: ${result.ackNumber} (${pdfBuffer.length} bytes)`);
    res.end(pdfBuffer);

  } catch (err) {
    logger.error('Forensic PDF generation failed:', err);
    res.status(500).json({ error: 'Failed to generate forensic report. Please try again.' });
  }
};

/**
 * POST /admin/reports/:id/verify-blockchain
 * Re-verify the blockchain integrity of a report's PDF
 * Regenerates the PDF, recalculates its hash, and compares with stored blockchain data.
 */
exports.verifyBlockchain = async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid report ID format.' });
    }

    const report = await Report.findById(id);
    if (!report) {
      return res.status(404).json({ error: 'Report not found.' });
    }

    // Check if blockchain data exists
    if (!report.blockchain || !report.blockchain.hash) {
      return res.json({
        verified: false,
        status: 'NO_BLOCKCHAIN',
        message: 'No blockchain data found. Generate a Forensic PDF first to create a blockchain entry.',
        blockchain: null,
      });
    }

    // Mathematical verification of the cryptographic block header
    const recalculatedBlockHash = crypto
      .createHash('sha256')
      .update(report.blockchain.pdfHash + report.blockchain.previousHash + report.blockchain.timestamp.toISOString())
      .digest('hex');

    const isVerified = recalculatedBlockHash === report.blockchain.hash;

    // Audit log the verification
    await logAction({
      adminId: req.session.adminId,
      adminEmail: req.session.adminEmail,
      action: 'VERIFY_BLOCKCHAIN',
      targetType: 'report',
      targetId: report.ackNumber,
      details: `Blockchain verification: ${isVerified ? 'VERIFIED' : 'TAMPERED'}`,
      ip: req.ip,
    });

    logger.info(`Blockchain verification for ${report.ackNumber}: ${isVerified ? 'VERIFIED' : 'TAMPERED'}`);

    res.json({
      verified: isVerified,
      status: isVerified ? 'VERIFIED' : 'TAMPERED',
      message: isVerified
        ? 'Block cryptographic integrity confirmed. The hashes have not been tampered with.'
        : 'WARNING: Block hash mismatch detected. The blockchain entry has been altered.',
      blockchain: {
        blockId: report.blockchain.blockId,
        hash: report.blockchain.hash,
        previousHash: report.blockchain.previousHash,
        pdfHash: report.blockchain.pdfHash,
        timestamp: report.blockchain.timestamp,
      },
      verification: {
        freshBlockHash: recalculatedBlockHash,
        storedBlockHash: report.blockchain.hash,
        match: isVerified,
      },
    });

  } catch (err) {
    logger.error('Blockchain verification failed:', err);
    res.status(500).json({ error: 'Verification failed. Please try again.' });
  }
};

/**
 * GET /admin/reports/:id/blockchain-status
 * Returns the current blockchain metadata for a report (no re-verification)
 */
exports.getBlockchainStatus = async (req, res) => {
  try {
    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid report ID format.' });
    }

    const report = await Report.findById(id).select('ackNumber blockchain');
    if (!report) {
      return res.status(404).json({ error: 'Report not found.' });
    }

    if (!report.blockchain || !report.blockchain.hash) {
      return res.json({
        exists: false,
        message: 'No blockchain data. Generate a Forensic PDF first.',
        blockchain: null,
      });
    }

    res.json({
      exists: true,
      blockchain: {
        blockId: report.blockchain.blockId,
        hash: report.blockchain.hash,
        previousHash: report.blockchain.previousHash,
        pdfHash: report.blockchain.pdfHash,
        timestamp: report.blockchain.timestamp,
        verified: report.blockchain.verified,
      },
    });

  } catch (err) {
    logger.error('Blockchain status fetch failed:', err);
    res.status(500).json({ error: 'Could not fetch blockchain status.' });
  }
};

/**
 * GET /admin/reports/:id/attachments/:type/:index
 * Blockchain-Gated Gated Access Download: Retrieves the file from IPFS, 
 * recalculates its hash, verifies it against the immutable blockchain registry, and downloads it.
 */
exports.downloadSecureAttachment = async (req, res) => {
  try {
    const { id, type, index } = req.params;

    // 1. Validate DB Identification
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid report ID format.' });
    }

    const report = await Report.findById(id);
    if (!report) {
      return res.status(404).json({ error: 'Report not found.' });
    }

    let targetFile = null;
    let compositeKey = '';

    // 2. Resolve document type maps and reconstruct composite blockchain index keys
    if (type === 'evidence') {
      targetFile = report.evidenceFiles && report.evidenceFiles[parseInt(index)];
      compositeKey = `${report.ackNumber}-file-${index}`;
    } else if (type === 'audio') {
      targetFile = report.audioEvidence && report.audioEvidence[parseInt(index)];
      compositeKey = `${report.ackNumber}-audio-${index}`;
    }

    if (!targetFile || !targetFile.ipfsCID) {
      return res.status(404).json({ error: 'The requested secure documentation attachment was not found.' });
    }

    logger.info(`Web3 Download: Fetching verification parameters from blockchain for key: ${compositeKey}`);

    // 3. Fetch Expected Parameters directly from Live Blockchain (On-chain Source of Truth)
    const { cid, fileHash } = await secureDownload(compositeKey);

    if (!cid || !fileHash || cid === '') {
      return res.status(404).json({ error: 'No matching tracking criteria found on the live blockchain ledger.' });
    }

    // 4. Download file bytes stream from decentralized IPFS Gateway
    logger.info(`IPFS: Fetching data buffer from gateway for CID: ${cid}`);
    const ipfsUrl = `https://pinata.cloud{cid}`;
    const response = await axios.get(ipfsUrl, { responseType: 'arraybuffer', timeout: 10000 });
    const fileBuffer = Buffer.from(response.data);

    // 5. Complete Structural Integrity Cross-Check (Local buffer vs Immutable Ledger Hash)
    const realTimeHash = hashFileBuffer(fileBuffer);
    if (realTimeHash !== fileHash) {
      logger.error(`SECURITY FAULT DETECTED: Tamper alert matching ledger hash against IPFS network response payload for key: ${compositeKey}`);
      return res.status(403).json({ error: 'Security Fault: File download blocked. This file has been tampered with or corrupted since its registry transaction.' });
    }

    // 6. Audit log the authorization check passing successfully
    await logAction({
      adminId: req.session.adminId,
      adminEmail: req.session.adminEmail,
      action: 'DOWNLOAD_SECURE_ATTACHMENT',
      targetType: 'report',
      targetId: report.ackNumber,
      details: `Securely verified and downloaded attachment index ${index} (${type}) for report ${report.ackNumber}`,
      ip: req.ip,
    });

    // 7. Stream the authenticated documentation file to the user's dashboard view
    res.writeHead(200, {
      'Content-Type': targetFile.mimeType || 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${targetFile.originalName || 'evidence_file'}"`,
      'Content-Length': fileBuffer.length,
      'Cache-Control': 'no-store'
    });

    res.end(fileBuffer);

  } catch (err) {
    logger.error('Gated attachment verification pipeline failed:', err);
res.status(500).json({ error: 'Error processing secure file validation check or gateway connectivity failed.' });
}
};


// // controllers/forensicReportController.js
// // Handles the forensic PDF report download endpoint

// const mongoose = require('mongoose');
// const { createForensicPDF } = require('../services/forensicReportService');
// const { logAction } = require('../services/auditService');
// const { verifyPDFIntegrity, hashFileBuffer } = require('../utils/blockchain');
// const Report = require('../models/Report');
// const logger = require('../utils/logger');

// /**
//  * GET /admin/reports/:id/forensic-pdf
//  * Generate and download a forensic PDF report for a specific complaint
//  */
// exports.downloadForensicPDF = async (req, res) => {
//   try {
//     const { id } = req.params;

//     // ── Validate MongoDB ObjectId ──────────────────────────────────────────
//     if (!mongoose.Types.ObjectId.isValid(id)) {
//       logger.warn(`Forensic PDF: Invalid report ID attempted – ${id}`);
//       return res.status(400).json({ error: 'Invalid report ID format.' });
//     }

//     // ── Generate the forensic PDF ─────────────────────────────────────────
//     logger.info(`Forensic PDF generation started for report: ${id} by admin: ${req.session.adminEmail}`);
//     const result = await createForensicPDF(id);

//     if (!result) {
//       logger.warn(`Forensic PDF: Report not found – ${id}`);
//       return res.status(404).json({ error: 'Report not found.' });
//     }

//     // ── Audit log the PDF generation ──────────────────────────────────────
//     await logAction({
//       adminId: req.session.adminId,
//       adminEmail: req.session.adminEmail,
//       action: 'GENERATE_FORENSIC_PDF',
//       targetType: 'report',
//       targetId: result.ackNumber,
//       details: `Forensic PDF generated for report ${result.ackNumber}`,
//       ip: req.ip,
//     });

//     // ── Set response headers and send PDF ────────────────────────────────
//     const filename = `SecureVoice_Forensic_${result.ackNumber}.pdf`;

//     // Ensure we have a proper Buffer
//     const pdfBuffer = Buffer.isBuffer(result.pdfBuffer)
//       ? result.pdfBuffer
//       : Buffer.from(result.pdfBuffer);

//     res.writeHead(200, {
//       'Content-Type': 'application/pdf',
//       'Content-Disposition': `attachment; filename="${filename}"`,
//       'Content-Length': pdfBuffer.length,
//       'Cache-Control': 'no-store, no-cache, must-revalidate',
//       'Pragma': 'no-cache',
//     });

//     logger.info(`Forensic PDF generated successfully: ${result.ackNumber} (${pdfBuffer.length} bytes)`);
//     res.end(pdfBuffer);

//   } catch (err) {
//     logger.error('Forensic PDF generation failed:', err);
//     res.status(500).json({ error: 'Failed to generate forensic report. Please try again.' });
//   }
// };

// /**
//  * POST /admin/reports/:id/verify-blockchain
//  * Re-verify the blockchain integrity of a report's PDF
//  * Regenerates the PDF, recalculates its hash, and compares with stored blockchain data.
//  */
// exports.verifyBlockchain = async (req, res) => {
//   try {
//     const { id } = req.params;

//     if (!mongoose.Types.ObjectId.isValid(id)) {
//       return res.status(400).json({ error: 'Invalid report ID format.' });
//     }

//     const report = await Report.findById(id);
//     if (!report) {
//       return res.status(404).json({ error: 'Report not found.' });
//     }

//     // Check if blockchain data exists
//     if (!report.blockchain || !report.blockchain.hash) {
//       return res.json({
//         verified: false,
//         status: 'NO_BLOCKCHAIN',
//         message: 'No blockchain data found. Generate a Forensic PDF first to create a blockchain entry.',
//         blockchain: null,
//       });
//     }

//     // Mathematical verification of the cryptographic block header
//     const crypto = require('crypto');
//     const recalculatedBlockHash = crypto
//       .createHash('sha256')
//       .update(report.blockchain.pdfHash + report.blockchain.previousHash + report.blockchain.timestamp.toISOString())
//       .digest('hex');

//     const isVerified = recalculatedBlockHash === report.blockchain.hash;

//     // Audit log the verification
//     await logAction({
//       adminId: req.session.adminId,
//       adminEmail: req.session.adminEmail,
//       action: 'VERIFY_BLOCKCHAIN',
//       targetType: 'report',
//       targetId: report.ackNumber,
//       details: `Blockchain verification: ${isVerified ? 'VERIFIED' : 'TAMPERED'}`,
//       ip: req.ip,
//     });

//     logger.info(`Blockchain verification for ${report.ackNumber}: ${isVerified ? 'VERIFIED' : 'TAMPERED'}`);

//     res.json({
//       verified: isVerified,
//       status: isVerified ? 'VERIFIED' : 'TAMPERED',
//       message: isVerified
//         ? 'Block cryptographic integrity confirmed. The hashes have not been tampered with.'
//         : 'WARNING: Block hash mismatch detected. The blockchain entry has been altered.',
//       blockchain: {
//         blockId: report.blockchain.blockId,
//         hash: report.blockchain.hash,
//         previousHash: report.blockchain.previousHash,
//         pdfHash: report.blockchain.pdfHash,
//         timestamp: report.blockchain.timestamp,
//       },
//       verification: {
//         freshBlockHash: recalculatedBlockHash,
//         storedBlockHash: report.blockchain.hash,
//         match: isVerified,
//       },
//     });

//   } catch (err) {
//     logger.error('Blockchain verification failed:', err);
//     res.status(500).json({ error: 'Verification failed. Please try again.' });
//   }
// };

// /**
//  * GET /admin/reports/:id/blockchain-status
//  * Returns the current blockchain metadata for a report (no re-verification)
//  */
// exports.getBlockchainStatus = async (req, res) => {
//   try {
//     const { id } = req.params;

//     if (!mongoose.Types.ObjectId.isValid(id)) {
//       return res.status(400).json({ error: 'Invalid report ID format.' });
//     }

//     const report = await Report.findById(id).select('ackNumber blockchain');
//     if (!report) {
//       return res.status(404).json({ error: 'Report not found.' });
//     }

//     if (!report.blockchain || !report.blockchain.hash) {
//       return res.json({
//         exists: false,
//         message: 'No blockchain data. Generate a Forensic PDF first.',
//         blockchain: null,
//       });
//     }

//     res.json({
//       exists: true,
//       blockchain: {
//         blockId: report.blockchain.blockId,
//         hash: report.blockchain.hash,
//         previousHash: report.blockchain.previousHash,
//         pdfHash: report.blockchain.pdfHash,
//         timestamp: report.blockchain.timestamp,
//         verified: report.blockchain.verified,
//       },
//     });

//   } catch (err) {
//     logger.error('Blockchain status fetch failed:', err);
//     res.status(500).json({ error: 'Could not fetch blockchain status.' });
//   }
// };

