import mongoose from 'mongoose';

// Egy beágyazott séma a konkrét megtalált hibáknak
const vulnerabilitySchema = new mongoose.Schema({
    owaspCategory: {
        type: String,
        required: true,
    },
    endpoint: {
        type: String,
        required: true
    },
    method: {
        type: String,
        required: true,
        uppercase: true
        // Pl.: 'DELETE', 'POST'
    },
    severity: {
        type: String,
        enum: ['Info', 'Low', 'Medium', 'High', 'Critical'],
        required: true
    },
    confidence: {
        type: String,
        enum: ['warning', 'danger'],
        required: true,
        default: 'warning'
    },
    description: {
        type: String
    },
    payloadUsed: {
        type: String
    }
}, { _id: false }); // Felesleges külön _id-t generálni a beágyazott elemeknek

// A fő vizsgálati riport sémája
const scanReportSchema = new mongoose.Schema({
    targetUrl: {
        type: String,
        required: true,
        trim: true
    },
    openApiSpecUrl: {
        type: String,
        trim: true
    },
    status: {
        type: String,
        enum: ['pending', 'running', 'completed', 'failed'],
        default: 'pending'
    },
    initiatedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    startTime: {
        type: Date,
        default: Date.now
    },
    endTime: {
        type: Date
    },
    totalEndpointsScanned: {
        type: Number,
        default: 0
    },
    errorMessage: {
        type: String // Sikertelen (failed) vizsgálat esetén az ok
    },
    vulnerabilities: [vulnerabilitySchema] // A beágyazott hibák tömbje
}, { timestamps: true });

const ScanReport = mongoose.model('ScanReport', scanReportSchema);
export default ScanReport;
