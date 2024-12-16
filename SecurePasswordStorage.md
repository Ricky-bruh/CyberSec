# Secure Password Storage: Theoretical & Implementation Guide

## Table of Contents
- [Password Storage Theory](#password-storage-theory)
- [Cryptographic Hash Functions](#cryptographic-hash-functions)
- [Salt & Pepper Theory](#salt--pepper-theory)
- [Key Derivation Functions](#key-derivation-functions)
- [Attack Vectors](#attack-vectors)
- [Implementation Guidelines](#implementation-guidelines)
- [Password Recovery](#password-recovery)
- [Emergency Response](#emergency-response)

## Password Storage Theory

### Cryptographic Principles

#### 1. One-Way Functions
- Computationally infeasible to reverse
- Small changes cause large output differences
- Fixed output length regardless of input
- Deterministic output for same input

#### 2. Security Properties
- **Pre-image resistance**: Cannot find input from output
- **Second pre-image resistance**: Cannot find another input with same output
- **Collision resistance**: Cannot find any two inputs with same output

#### 3. Entropy Considerations
- **Password Space**: 94^n for printable ASCII
- **Effective Entropy**: ~6.5 bits per character
- **Minimum Entropy Requirements**:
  - Online attacks: 40 bits
  - Offline attacks: 80 bits
  - Future-proof: 128 bits

### Password Transformation Chain

1. **Initial Processing**
```plaintext
Raw Password → Normalized Form → Encoded Bytes
```

2. **Cryptographic Processing**
```plaintext
Encoded Bytes → Salt Addition → Key Derivation → Final Hash
```

3. **Storage Format**
```plaintext
$algorithm$iterations$salt$hash
```

## Cryptographic Hash Functions

### Algorithm Characteristics

1. **MD5 (Obsolete)**
- 128-bit output
- 512-bit block size
- Vulnerable to:
  - Collision attacks
  - Length extension
  - Rainbow tables

2. **SHA-1 (Deprecated)**
- 160-bit output
- 512-bit block size
- Known vulnerabilities:
  - Collision attacks
  - Chosen-prefix collisions
  - Length extension

3. **SHA-2 Family**
- SHA-256:
  - 256-bit output
  - 512-bit block size
  - 64 rounds
- SHA-512:
  - 512-bit output
  - 1024-bit block size
  - 80 rounds

4. **SHA-3 Family**
- Based on Keccak sponge function
- Variable output lengths:
  - SHA3-256: 256-bit output
  - SHA3-512: 512-bit output
- No length extension vulnerability

### Algorithm Weaknesses

1. **Speed-Based Attacks**
```plaintext
Hash Speed (Rough Estimates on Modern GPU):
- MD5:    12.5 billion/second
- SHA-1:   5.0 billion/second
- SHA-256: 2.5 billion/second
- SHA-3:   1.5 billion/second
```

2. **Parallel Processing Vulnerability**
- Multiple GPU utilization
- ASIC optimization
- Cloud computing scalability
- Distributed cracking

## Salt & Pepper Theory

### Salt Properties

1. **Cryptographic Requirements**
- Minimum length: 16 bytes
- True randomness (not pseudo-random)
- Unique per password
- Never reused

2. **Purpose Analysis**
- Prevents rainbow tables
- Makes identical passwords unique
- Increases attack complexity
- Per-user uniqueness guarantee

### Pepper Properties

1. **Cryptographic Requirements**
- Server-side secret
- Application-wide constant
- High entropy requirement
- Secure storage separate from database

2. **Security Benefits**
- Additional layer of protection
- Database compromise mitigation
- Increased crack complexity
- Hardware security module integration

### Combined Usage Theory

1. **Operation Order**
```plaintext
password + salt → hash → pepper → final hash
```

2. **Security Implications**
- Two-factor compromise requirement
- Increased brute force complexity
- Rainbow table invalidation
- Per-application uniqueness

## Key Derivation Functions

### PBKDF2 Analysis

1. **Function Properties**
- NIST approved (SP 800-132)
- Configurable iterations
- Salt support
- Adjustable output length

2. **Security Characteristics**
```plaintext
Security Level = HashMap(
    iterations * hash_complexity,
    memory_usage,
    parallelization_resistance
)
```

### Bcrypt Fundamentals

1. **Algorithm Properties**
- Based on Blowfish cipher
- Built-in salt management
- Configurable work factor
- Memory-hard function

2. **Work Factor Analysis**
```plaintext
Time = O(2^work_factor)
Memory = O(2^work_factor)
```

### Argon2 Architecture

1. **Variants**
- Argon2d: Data-dependent
- Argon2i: Data-independent
- Argon2id: Hybrid approach

2. **Parameter Space**
```plaintext
Security = Function(
    memory_size,
    iterations,
    parallelism,
    tag_length
)
```

### Scrypt Design

1. **Resource Requirements**
- CPU-intensive operations
- Memory-hard calculations
- Time-memory tradeoff resistance
- Sequential memory hardness

2. **Parameter Selection**
```plaintext
N: CPU/Memory cost
r: Block size
p: Parallelization factor

Memory = O(N * r)
Time = O(N * r * p)
```

## Attack Vectors

### Offline Attacks

1. **Dictionary Attacks**
- Word list based
- Rule-based mutations
- Language-specific patterns
- Common substitutions

2. **Brute Force Patterns**
```plaintext
Complexity = character_set_size ^ password_length
Time_to_crack = complexity / hash_rate
```

### Hardware Acceleration

1. **GPU Optimization**
- Parallel hash computation
- Memory optimization
- Instruction-level parallelism
- Stream processing

2. **ASIC Capabilities**
```plaintext
Performance Ratios (Approximate):
CPU: 1x baseline
GPU: 100x CPU
ASIC: 1000x GPU
```

### Time-Memory Tradeoffs

1. **Rainbow Tables**
- Pre-computed hash chains
- Storage vs computation tradeoff
- Chain length optimization
- Success probability

2. **Perfect Tables**
```plaintext
Storage = hash_size * number_of_passwords
Time = O(1)
Success_rate = stored_passwords / possible_passwords
```

## Implementation Guidelines

### Hash Function Implementation

1. **Modern Hash Generation**
```javascript
// Argon2 Implementation
const argon2 = require('argon2');

const hashPassword = async (password) => {
    try {
        return await argon2.hash(password, {
            type: argon2.argon2id,
            memoryCost: 2 ** 16,  // 64MB memory usage
            timeCost: 3,          // 3 iterations
            parallelism: 2,       // 2 parallel threads
            hashLength: 32,       // 32-byte output
            saltLength: 16        // 16-byte salt
        });
    } catch (err) {
        throw new Error('Hash generation failed');
    }
};

// Bcrypt Implementation with Salt Rounds
const bcrypt = require('bcrypt');

const hashPasswordBcrypt = async (password) => {
    const saltRounds = 12;  // 2^12 iterations
    try {
        const salt = await bcrypt.genSalt(saltRounds);
        return await bcrypt.hash(password, salt);
    } catch (err) {
        throw new Error('Bcrypt hash generation failed');
    }
};
```

2. **Pepper Integration**
```typescript
interface PepperConfig {
    algorithm: string;
    keySize: number;
    iterations: number;
}

class PepperHasher {
    private pepper: Buffer;
    private config: PepperConfig;

    constructor(pepper: string, config: PepperConfig) {
        this.pepper = Buffer.from(pepper, 'hex');
        this.config = config;
    }

    async hashWithPepper(password: string): Promise<string> {
        const argonHash = await argon2.hash(password);
        const pepperMaterial = Buffer.concat([
            Buffer.from(argonHash),
            this.pepper
        ]);
        
        const hmac = crypto.createHmac('sha512', this.pepper);
        hmac.update(pepperMaterial);
        
        return hmac.digest('base64');
    }
}
```

### Password Validation Implementation

```javascript
class PasswordValidator {
    constructor(config) {
        this.minLength = config.minLength || 8;
        this.maxLength = config.maxLength || 128;
        this.requireUppercase = config.requireUppercase || true;
        this.requireLowercase = config.requireLowercase || true;
        this.requireNumbers = config.requireNumbers || true;
        this.requireSpecial = config.requireSpecial || true;
    }

    validate(password) {
        const errors = [];

        if (password.length < this.minLength) {
            errors.push(`Password must be at least ${this.minLength} characters`);
        }

        if (password.length > this.maxLength) {
            errors.push(`Password must be less than ${this.maxLength} characters`);
        }

        if (this.requireUppercase && !/[A-Z]/.test(password)) {
            errors.push('Password must contain uppercase letters');
        }

        if (this.requireLowercase && !/[a-z]/.test(password)) {
            errors.push('Password must contain lowercase letters');
        }

        if (this.requireNumbers && !/[0-9]/.test(password)) {
            errors.push('Password must contain numbers');
        }

        if (this.requireSpecial && !/[^A-Za-z0-9]/.test(password)) {
            errors.push('Password must contain special characters');
        }

        return {
            isValid: errors.length === 0,
            errors
        };
    }
}
```

### Hash Upgrade Strategy

```typescript
interface HashUpgradeStrategy {
    readonly oldAlgorithm: string;
    readonly newAlgorithm: string;
    needsUpgrade(hash: string): boolean;
    upgradeHash(password: string, oldHash: string): Promise<string>;
}

class HashUpgrader implements HashUpgradeStrategy {
    private hasher: AdaptiveHasher;

    constructor(oldAlgo: string, newAlgo: string) {
        this.oldAlgorithm = oldAlgo;
        this.newAlgorithm = newAlgo;
        this.hasher = new AdaptiveHasher();
    }

    needsUpgrade(hash: string): boolean {
        const [algorithm] = hash.split('$');
        return algorithm !== this.newAlgorithm;
    }

    async upgradeHash(password: string, oldHash: string): Promise<string> {
        if (!await this.verifyOldHash(password, oldHash)) {
            throw new Error('Invalid password');
        }
        return await this.hasher.hashPassword(password, this.newAlgorithm);
    }
}
```

## Password Recovery

### Secure Reset Implementation

```javascript
class PasswordReset {
    constructor(config) {
        this.tokenExpiry = config.tokenExpiry || 3600; // 1 hour
        this.tokenLength = config.tokenLength || 32;
    }

    async generateResetToken(userId) {
        const token = crypto.randomBytes(this.tokenLength).toString('hex');
        const expiresAt = Date.now() + (this.tokenExpiry * 1000);
        
        const hashedToken = await argon2.hash(token);
        
        await db.passwordResets.create({
            userId,
            tokenHash: hashedToken,
            expiresAt
        });
        
        return token;
    }

    async verifyResetToken(userId, token) {
        const reset = await db.passwordResets.findOne({
            where: {
                userId,
                expiresAt: { $gt: Date.now() }
            }
        });

        if (!reset) {
            throw new Error('Invalid or expired reset token');
        }

        const isValid = await argon2.verify(reset.tokenHash, token);
        if (!isValid) {
            throw new Error('Invalid reset token');
        }

        await db.passwordResets.delete({ userId });
        return true;
    }
}
```

### Rate Limiting

```javascript
class ResetRateLimiter {
    constructor(redis) {
        this.redis = redis;
        this.maxAttempts = 3;
        this.windowSeconds = 3600; // 1 hour
    }

    async checkRateLimit(userId) {
        const key = `reset_attempt:${userId}`;
        const attempts = await this.redis.incr(key);
        
        if (attempts === 1) {
            await this.redis.expire(key, this.windowSeconds);
        }
        
        if (attempts > this.maxAttempts) {
            throw new Error('Too many reset attempts');
        }
        
        return this.maxAttempts - attempts;
    }
}
```

## Emergency Response

### Breach Detection

```javascript
class PasswordBreachDetector {
    async checkPasswordLeak(password) {
        // Using k-anonymity with HIBP API
        const hash = crypto.createHash('sha1')
            .update(password)
            .digest('hex')
            .toUpperCase();
        
        const prefix = hash.slice(0, 5);
        const suffix = hash.slice(5);
        
        const response = await fetch(
            `https://api.pwnedpasswords.com/range/${prefix}`
        );
        
        const hashes = await response.text();
        const breachCount = this.findHashInResponse(hashes, suffix);
        
        return {
            isBreached: breachCount > 0,
            breachCount
        };
    }

    private findHashInResponse(hashes: string, suffix: string): number {
        const lines = hashes.split('\n');
        const match = lines.find(line => line.startsWith(suffix));
        return match ? parseInt(match.split(':')[1]) : 0;
    }
}
```

### Emergency Password Change

```javascript
class EmergencyPasswordChange {
    constructor(hasher, validator, breachDetector) {
        this.hasher = hasher;
        this.validator = validator;
        this.breachDetector = breachDetector;
    }

    async forcePasswordChange(userId, newPassword) {
        // Validate new password
        const validationResult = this.validator.validate(newPassword);
        if (!validationResult.isValid) {
            throw new Error('Invalid password');
        }

        // Check for breaches
        const breachCheck = await this.breachDetector
            .checkPasswordLeak(newPassword);
        if (breachCheck.isBreached) {
            throw new Error('Password found in data breach');
        }

        // Hash new password
        const hashedPassword = await this.hasher
            .hashPassword(newPassword);

        // Update in database with audit trail
        await db.transaction(async (t) => {
            await db.users.update({
                passwordHash: hashedPassword,
                passwordChangedAt: new Date(),
                requirePasswordChange: false
            }, {
                where: { id: userId },
                transaction: t
            });

            await db.passwordChangeLog.create({
                userId,
                changeType: 'emergency',
                timestamp: new Date()
            }, {
                transaction: t
            });
        });

        // Invalidate all sessions
        await this.invalidateUserSessions(userId);
    }
}
```
## Additional Resources
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)
- [Argon2 Reference Implementation](https://github.com/P-H-C/phc-winner-argon2)
- [Password Strength Testing Tool](https://github.com/dropbox/zxcvbn)
- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)

## Contributing
Feel free to contribute to this guide by:
1. Opening issues
2. Submitting pull requests
3. Suggesting improvements
4. Reporting bugs

## License
This document is licensed under MIT License.

## Disclaimer
This guide is for educational purposes only. Always follow applicable laws and regulations, and only test security on systems you own or have explicit permission to test.
