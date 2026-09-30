const mongoose = require('mongoose');

const incidentSchema = new mongoose.Schema({
    incidentId: { type: String, required: true, unique: true },
    description: { type: String, required: true },
    // ADD THESE TWO FIELDS TO YOUR EXISTING SCHEMA:
    ipfsCID: { type: String, default: null },
    fileHash: { type: String, default: null },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Incident', incidentSchema);
