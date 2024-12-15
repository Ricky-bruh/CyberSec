# Secure File Upload: Complete Implementation Guide

## Table of Contents
- [Understanding File Upload Risks](#understanding-file-upload-risks)
- [Security Measures](#security-measures)
- [Implementation Guide](#implementation-guide)
- [Storage Solutions](#storage-solutions)
- [Processing & Validation](#processing--validation)
- [Emergency Response](#emergency-response)

## Understanding File Upload Risks

### Common Attack Vectors
1. Malicious File Contents:
   - Executable files (.exe, .bat)
   - Script files (.php, .js)
   - Shell scripts (.sh)
   - Web shells
   - Malware-infected files

2. File Type Exploits:
   - MIME type spoofing
   - Extension manipulation
   - Polyglot files
   - ZIP bombs
   - File type confusion

3. Server-Side Risks:
   - Directory traversal
   - Path manipulation
   - Disk space exhaustion
   - Race conditions
   - Symbolic link attacks

## Security Measures

### File Validation

1. MIME Type Check:
```javascript
const validateMimeType = (file) => {
  const allowedTypes = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ];
  
  return allowedTypes.includes(file.mimetype);
};
```

2. File Extension Validation:
```javascript
const validateExtension = (filename) => {
  const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx'];
  const ext = path.extname(filename).toLowerCase();
  
  return allowedExtensions.includes(ext);
};
```

3. Content Analysis:
```javascript
const fileType = require('file-type');

const analyzeContent = async (buffer) => {
  const type = await fileType.fromBuffer(buffer);
  
  if (!type) {
    throw new Error('Unable to determine file type');
  }
  
  // Compare with claimed MIME type
  if (type.mime !== claimedMimeType) {
    throw new Error('MIME type mismatch');
  }
  
  return type;
};
```

### Implementation Guide

1. Basic Express Implementation:
```javascript
const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const path = require('path');

// Configure storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    // Generate random filename
    crypto.randomBytes(16, (err, raw) => {
      if (err) return cb(err);
      
      cb(null, raw.toString('hex') + path.extname(file.originalname));
    });
  }
});

// Configure upload limits
const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 1
  },
  fileFilter: (req, file, cb) => {
    if (!validateMimeType(file)) {
      return cb(new Error('Invalid file type'), false);
    }
    
    if (!validateExtension(file.originalname)) {
      return cb(new Error('Invalid file extension'), false);
    }
    
    cb(null, true);
  }
});
```

2. Complete Upload Handler:
```javascript
app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    // Analyze file content
    const buffer = await fs.promises.readFile(req.file.path);
    await analyzeContent(buffer);
    
    // Scan for malware (example using ClamAV)
    const isClean = await scanFile(req.file.path);
    if (!isClean) {
      await fs.promises.unlink(req.file.path);
      return res.status(400).json({ error: 'Malicious file detected' });
    }
    
    // Process file (e.g., generate thumbnail, extract metadata)
    await processFile(req.file);
    
    // Store file metadata in database
    await storeFileMetadata(req.file);
    
    res.json({
      message: 'File uploaded successfully',
      filename: req.file.filename
    });
  } catch (error) {
    // Clean up on error
    if (req.file) {
      await fs.promises.unlink(req.file.path);
    }
    
    res.status(500).json({ error: error.message });
  }
});
```

### Storage Solutions

1. Local Storage Configuration:
```javascript
const storeLocal = {
  async save(file) {
    const filename = await generateSecureFilename(file);
    const filepath = path.join(process.env.UPLOAD_DIR, filename);
    
    // Ensure directory exists
    await fs.promises.mkdir(process.env.UPLOAD_DIR, { recursive: true });
    
    // Move file to final location
    await fs.promises.rename(file.path, filepath);
    
    return filename;
  },
  
  async delete(filename) {
    const filepath = path.join(process.env.UPLOAD_DIR, filename);
    await fs.promises.unlink(filepath);
  }
};
```

2. S3 Storage Configuration:
```javascript
const AWS = require('aws-sdk');
const s3 = new AWS.S3();

const storeS3 = {
  async save(file) {
    const filename = await generateSecureFilename(file);
    
    await s3.upload({
      Bucket: process.env.S3_BUCKET,
      Key: filename,
      Body: fs.createReadStream(file.path),
      ContentType: file.mimetype,
      ServerSideEncryption: 'AES256'
    }).promise();
    
    return filename;
  },
  
  async delete(filename) {
    await s3.deleteObject({
      Bucket: process.env.S3_BUCKET,
      Key: filename
    }).promise();
  }
};
```

### Processing & Validation

1. Image Processing:
```javascript
const sharp = require('sharp');

const processImage = async (file) => {
  const image = sharp(file.path);
  const metadata = await image.metadata();
  
  // Validate dimensions
  if (metadata.width > 4096 || metadata.height > 4096) {
    throw new Error('Image dimensions too large');
  }
  
  // Generate thumbnail
  await image
    .resize(200, 200, {
      fit: 'inside',
      withoutEnlargement: true
    })
    .jpeg({ quality: 80 })
    .toFile(`${file.path}_thumb.jpg`);
    
  return metadata;
};
```

2. PDF Processing:
```javascript
const pdf = require('pdf-parse');

const processPDF = async (file) => {
  const dataBuffer = await fs.promises.readFile(file.path);
  const data = await pdf(dataBuffer);
  
  // Validate page count
  if (data.numpages > 100) {
    throw new Error('PDF too large');
  }
  
  return {
    pages: data.numpages,
    info: data.info,
    metadata: data.metadata
  };
};
```

### Security Headers

```javascript
app.use((req, res, next) => {
  // Prevent browsers from MIME-sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // Prevent file from being embedded in other sites
  res.setHeader('Content-Disposition', 'attachment');
  
  // Set strict CSP for upload endpoints
  res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; connect-src 'self';");
  
  next();
});
```

## Emergency Response

### If Compromised

1. Immediate Actions:
```plaintext
1. Stop accepting new uploads
2. Isolate affected storage
3. Scan all existing files
4. Review access logs
5. Notify affected users
```

2. Prevention:
```javascript
// Implement rate limiting
const rateLimit = require('express-rate-limit');

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 uploads per window
  message: 'Too many uploads from this IP'
});

app.use('/upload', uploadLimiter);

// Implement file scanning
const scanFile = async (filepath) => {
  const scanner = new NodeClam();
  const {isInfected, viruses} = await scanner.scanFile(filepath);
  
  if (isInfected) {
    logger.error(`Malware detected: ${viruses.join(', ')}`);
    return false;
  }
  
  return true;
};
```

## Best Practices

### For Developers
1. Always validate files server-side
2. Use secure random filenames
3. Set appropriate file size limits
4. Implement virus scanning
5. Use secure storage solutions
6. Process files asynchronously
7. Implement proper error handling
8. Use rate limiting
9. Log all upload activities
10. Regular security audits

### For System Admins
1. Configure proper file permissions
2. Monitor disk space
3. Regular malware scans
4. Backup management
5. Access control implementation

## Additional Resources
- [OWASP File Upload Cheat Sheet](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [CWE-434: Unrestricted File Upload](https://cwe.mitre.org/data/definitions/434.html)
- [NIST Guidelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r4.pdf)

## Contributing
Feel free to contribute by:
1. Reporting security issues
2. Suggesting improvements
3. Adding new validations
4. Improving documentation

## License
MIT License

## Disclaimer
This guide is for educational purposes only. Always follow security best practices and applicable regulations in your jurisdiction.
