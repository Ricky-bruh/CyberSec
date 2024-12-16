# API Security: Technical Implementation Guide

## Table of Contents
- [Authentication Exploits](#authentication-exploits)
- [Input Validation Attacks](#input-validation-attacks)
- [API Rate Abuse](#api-rate-abuse)
- [Version-based Attacks](#version-based-attacks)
- [Error Information Leakage](#error-information-leakage)
- [Defense Strategies](#defense-strategies)

## Authentication Exploits

### JWT Token Manipulation
```javascript
// Vulnerable implementation
const verifyToken = (token) => {
    return jwt.verify(token, process.env.JWT_SECRET);
};

// Attack example
// 1. Decode JWT without verification
const decodedToken = jwt.decode(token);
// 2. Modify payload
decodedToken.role = 'admin';
// 3. Create new token with none algorithm
const fakeToken = jwt.sign(decodedToken, '', { algorithm: 'none' });
```

#### How It Works
1. Token algorithm switched to 'none'
2. Payload modified without detection
3. Server accepts unverified token
4. Privilege escalation achieved

#### Defense Strategies
```javascript
// Secure JWT verification
const verifyToken = (token) => {
    try {
        // Force specific algorithm
        return jwt.verify(token, process.env.JWT_SECRET, {
            algorithms: ['HS256'],
            issuer: 'auth.yourapi.com',
            audience: 'yourapi.com',
            maxAge: '1h'
        });
    } catch (err) {
        if (err instanceof jwt.TokenExpiredError) {
            throw new Error('Token expired');
        }
        throw new Error('Invalid token');
    }
};

// Token creation with secure defaults
const generateToken = (payload) => {
    return jwt.sign(payload, process.env.JWT_SECRET, {
        algorithm: 'HS256',
        expiresIn: '1h',
        notBefore: '0s',
        audience: 'yourapi.com',
        issuer: 'auth.yourapi.com',
        jwtid: crypto.randomBytes(16).toString('hex')
    });
};
```

### OAuth Token Theft
```javascript
// Vulnerable redirect
app.get('/oauth/callback', (req, res) => {
    const { code } = req.query;
    // No state validation
    exchangeCodeForToken(code);
});

// Attack
// 1. Initiate OAuth flow
// 2. Intercept callback with code
// 3. Use code before legitimate user
```

#### How It Works
1. Missing state parameter check
2. CSRF vulnerability
3. Code interception possible
4. Token obtained by attacker

#### Defense
```javascript
// Secure OAuth implementation
const initiateOAuth = (req, res) => {
    const state = crypto.randomBytes(32).toString('hex');
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');
    
    // Store in session
    req.session.oauthState = state;
    req.session.codeVerifier = codeVerifier;
    
    const authUrl = new URL('https://auth-provider/oauth/authorize');
    authUrl.searchParams.set('client_id', CLIENT_ID);
    authUrl.searchParams.set('redirect_uri', REDIRECT_URI);
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    
    res.redirect(authUrl.toString());
};

const handleOAuthCallback = async (req, res) => {
    const { state, code } = req.query;
    
    // Validate state
    if (state !== req.session.oauthState) {
        throw new Error('OAuth state mismatch');
    }
    
    // Exchange code using PKCE
    const tokenResponse = await exchangeCodeForToken(
        code,
        req.session.codeVerifier
    );
    
    // Clear session data
    delete req.session.oauthState;
    delete req.session.codeVerifier;
    
    return tokenResponse;
};
```

## Input Validation Attacks

### NoSQL Injection
```javascript
// Vulnerable query
const user = await User.findOne({
    username: req.body.username,
    password: req.body.password
});

// Attack payload
{
    "username": {"$ne": null},
    "password": {"$ne": null}
}
```

#### How It Works
1. Query operators injected
2. Logical conditions modified
3. Authentication bypassed
4. Data leaked

#### Defense
```javascript
// Input sanitization
const sanitizeMongoQuery = (query) => {
    const sanitized = {};
    
    for (const [key, value] of Object.entries(query)) {
        // Prevent operator injection
        if (typeof value === 'object' && value !== null) {
            // Only allow specific operators
            const safeValue = {};
            const allowedOps = ['$eq', '$gt', '$lt', '$gte', '$lte'];
            
            for (const [op, opValue] of Object.entries(value)) {
                if (allowedOps.includes(op)) {
                    safeValue[op] = opValue;
                }
            }
            
            sanitized[key] = safeValue;
        } else {
            sanitized[key] = { $eq: value };
        }
    }
    
    return sanitized;
};

// Secure query building
const findUser = async (query) => {
    const sanitizedQuery = sanitizeMongoQuery(query);
    return await User.findOne(sanitizedQuery);
};
```

[Continuing in next message due to length...]

Would you like me to continue with the remaining sections, maintaining this technical style and format?
