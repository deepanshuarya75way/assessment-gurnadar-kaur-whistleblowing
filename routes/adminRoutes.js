// routes/adminRoutes.js
const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const adminController = require('../controllers/adminController');
const forensicReportController = require('../controllers/forensicReportController');
const { requireAdmin, redirectIfLoggedIn } = require('../middleware/auth');

// Strict rate limit on login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many login attempts. Try again in 15 minutes.',
});

// Auth routes (no admin guard)
router.get('/login', redirectIfLoggedIn, adminController.showLogin);
router.post('/login', loginLimiter, adminController.login);
router.post('/logout', requireAdmin, adminController.logout);

// Protected routes
router.get('/dashboard', requireAdmin, adminController.dashboard);
router.get('/reports', requireAdmin, adminController.listReports);
router.get('/reports/:id', requireAdmin, adminController.viewReport);
router.get('/reports/:id/forensic-pdf', requireAdmin, forensicReportController.downloadForensicPDF);
router.get('/reports/:id/blockchain-status', requireAdmin, forensicReportController.getBlockchainStatus);
router.post('/reports/:id/verify-blockchain', requireAdmin, forensicReportController.verifyBlockchain);
router.post('/reports/:id/status', requireAdmin, adminController.updateStatus);
router.get('/audit-logs', requireAdmin, adminController.auditLogs);

// Messaging & Audio Routes
router.post('/message/reply/:id', requireAdmin, adminController.replyMessage);
router.get('/audio/:filename', requireAdmin, adminController.serveAudio);

// ─── NEW DECENTRALIZED DATA VERIFICATION & GATED RETRIEVAL ROUTE ───
router.get('/reports/:id/attachments/:type/:index', requireAdmin, forensicReportController.downloadSecureAttachment);

module.exports = router;

