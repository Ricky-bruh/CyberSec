# CORS Security: Complete Implementation Guide

## Table of Contents
- [Understanding CORS](#understanding-cors)
- [Security Implications](#security-implications)
- [Implementation Guide](#implementation-guide)
- [Common Vulnerabilities](#common-vulnerabilities)
- [Framework-Specific Implementations](#framework-specific-implementations)
- [Headers Deep Dive](#headers-deep-dive)
- [Best Practices](#best-practices)
- [Emergency Response](#emergency-response)

## Understanding CORS

### Basic Concepts
Cross-Origin Resource Sharing (CORS) is a security mechanism that allows or restricts requested resources on a web server based on where the HTTP request originated from.

### CORS Flow
1. Browser initiates request to different origin
2. Server responds with CORS headers
3. Browser evaluates CORS headers
4. Request either proceeds or fails

### Key Headers
```http
Access-Control-Allow-Origin: https://trusted-site.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 3600
```

## Security Implications

### Risk Factors
1. Overly Permissive Configuration:
   - Using wildcard (*) origins
   - Allowing all headers
   - Enabling credentials globally

2. Insufficient Validation:
   - Not validating origins
   - Missing preflight checks
   - Weak origin matching

3. Information Exposure:
   - Sensitive headers exposure
   - Error message leakage
   - Credential mishandling

## Implementation Guide

### Node.js/Express Implementation
```javascript
const cors = require('cors');

// Basic Configuration
const corsOptions = {
  origin: (origin, callback) => {
    const whitelist = [
      'https://trusted-site.com',
      'https://api.trusted-site.com'
    ];
    
    if (whitelist.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  maxAge: 3600,
  preflightContinue: false,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));

// Route-specific CORS
app.get('/api/sensitive-data', cors({
  origin: 'https://admin.trusted-site.com',
  credentials: true
}), (req, res) => {
  // Handle request
});

// Dynamic CORS based on environment
const dynamicCors = {
  development: ['http://localhost:3000', 'http://localhost:8080'],
  production: ['https://trusted-site.com', 'https://api.trusted-site.com'],
  staging: ['https://staging.trusted-site.com']
};

const environmentCors = cors({
  origin: (origin, callback) => {
    const allowedOrigins = dynamicCors[process.env.NODE_ENV];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS not allowed'));
    }
  }
});
```

### Python/Flask Implementation
```python
from flask import Flask, request
from flask_cors import CORS

app = Flask(__name__)

# Configure CORS
cors_config = {
    "origins": ["https://trusted-site.com"],
    "methods": ["GET", "POST", "PUT", "DELETE"],
    "allow_headers": ["Content-Type", "Authorization"],
    "supports_credentials": True,
    "max_age": 3600
}

CORS(app, resources={
    r"/api/*": cors_config,
    r"/public/*": {"origins": "*"},  # Less restrictive for public routes
    r"/admin/*": {  # More restrictive for admin routes
        "origins": ["https://admin.trusted-site.com"],
        "supports_credentials": True
    }
})

# Custom CORS decorator
def custom_cors(*args, **kwargs):
    def decorator(f):
        def wrapped_function(*args, **kwargs):
            # Pre-flight request handling
            if request.method == 'OPTIONS':
                response = make_response()
                response.headers['Access-Control-Allow-Origin'] = kwargs.get('origin')
                response.headers['Access-Control-Allow-Methods'] = kwargs.get('methods')
                return response
            return f(*args, **kwargs)
        return wrapped_function
    return decorator
```

### Apache Configuration
```apache
# Enable CORS in .htaccess or apache config
<IfModule mod_headers.c>
    SetEnvIf Origin "^(https://trusted-site\.com)$" ORIGIN=$1
    Header set Access-Control-Allow-Origin "%{ORIGIN}e" env=ORIGIN
    Header set Access-Control-Allow-Methods "GET, POST, PUT, DELETE"
    Header set Access-Control-Allow-Headers "Content-Type, Authorization"
    Header set Access-Control-Allow-Credentials "true"
    Header set Access-Control-Max-Age "3600"
    
    # Handle OPTIONS preflight
    RewriteEngine On
    RewriteCond %{REQUEST_METHOD} OPTIONS
    RewriteRule ^(.*)$ $1 [R=200,L]
</IfModule>
```

### Nginx Configuration
```nginx
# CORS configuration in nginx.conf
map $http_origin $cors_origin {
    default "";
    "~^https://trusted-site\.com$" "$http_origin";
    "~^https://api\.trusted-site\.com$" "$http_origin";
}

server {
    location /api/ {
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' $cors_origin;
            add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS';
            add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization';
            add_header 'Access-Control-Allow-Credentials' 'true';
            add_header 'Access-Control-Max-Age' 3600;
            return 204;
        }
        
        add_header 'Access-Control-Allow-Origin' $cors_origin always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization' always;
        add_header 'Access-Control-Allow-Credentials' 'true' always;
        
        proxy_pass http://backend;
    }
}
```

## Common Vulnerabilities

### 1. Misconfigured Origins
```javascript
// VULNERABLE: Allows all origins
app.use(cors({
  origin: '*'
}));

// SECURE: Specific origin validation
app.use(cors({
  origin: (origin, callback) => {
    const trusted = ['https://trusted-site.com'];
    if (!origin || trusted.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed'));
    }
  }
}));
```

### 2. Weak Origin Validation
```javascript
// VULNERABLE: Weak validation
const isAllowed = (origin) => origin.endsWith('trusted-site.com');

// SECURE: Strict validation
const isAllowed = (origin) => {
  const url = new URL(origin);
  return url.protocol === 'https:' && 
         url.hostname === 'trusted-site.com';
};
```

### 3. Credential Exposure
```javascript
// VULNERABLE: Credentials with wildcard
app.use(cors({
  origin: '*',
  credentials: true  // This won't work with wildcard
}));

// SECURE: Proper credentials handling
app.use(cors({
  origin: 'https://trusted-site.com',
  credentials: true
}));
```

## Framework-Specific Implementations

### React Frontend
```javascript
// Fetch with CORS
const fetchData = async () => {
  try {
    const response = await fetch('https://api.example.com/data', {
      method: 'POST',
      credentials: 'include',  // For cookies
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(data)
    });
    
    if (!response.ok) {
      throw new Error('Network response was not ok');
    }
    
    return await response.json();
  } catch (error) {
    console.error('Error:', error);
    throw error;
  }
};
```

### Spring Boot Implementation
```java
@Configuration
public class CorsConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins("https://trusted-site.com")
            .allowedMethods("GET", "POST", "PUT", "DELETE")
            .allowedHeaders("Content-Type", "Authorization")
            .allowCredentials(true)
            .maxAge(3600);
    }
}

// Controller-level CORS
@CrossOrigin(
    origins = "https://trusted-site.com",
    methods = {RequestMethod.GET, RequestMethod.POST},
    allowedHeaders = {"Content-Type", "Authorization"},
    allowCredentials = "true",
    maxAge = 3600
)
@RestController
public class ApiController {
    // Controller methods
}
```

## Headers Deep Dive

### Essential Headers
1. Access-Control-Allow-Origin
```http
# Single origin
Access-Control-Allow-Origin: https://trusted-site.com

# Dynamic origin (from allowed list)
Access-Control-Allow-Origin: ${VALIDATED_ORIGIN}
```

2. Access-Control-Allow-Methods
```http
# Specific methods
Access-Control-Allow-Methods: GET, POST

# All methods (not recommended)
Access-Control-Allow-Methods: *
```

3. Access-Control-Allow-Headers
```http
# Common headers
Access-Control-Allow-Headers: Content-Type, Authorization

# Custom headers
Access-Control-Allow-Headers: X-Custom-Header, X-Requested-With
```

### Preflight Handling
```javascript
// Express middleware for preflight
app.options('*', (req, res) => {
  const origin = req.header('Origin');
  
  if (isAllowedOrigin(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Max-Age', '3600');
    res.sendStatus(204);
  } else {
    res.sendStatus(403);
  }
});
```

## Best Practices

### 1. Origin Validation
```javascript
const validateOrigin = (origin) => {
  // Parse origin URL
  try {
    const url = new URL(origin);
    
    // Check protocol
    if (url.protocol !== 'https:') {
      return false;
    }
    
    // Check domain and subdomain
    const domain = url.hostname;
    const allowedDomains = [
      'trusted-site.com',
      'api.trusted-site.com'
    ];
    
    return allowedDomains.includes(domain);
  } catch {
    return false;
  }
};
```

### 2. Environment-based Configuration
```javascript
const corsConfig = {
  development: {
    origin: ['http://localhost:3000'],
    credentials: true
  },
  production: {
    origin: ['https://trusted-site.com'],
    credentials: true,
    maxAge: 3600
  },
  testing: {
    origin: ['http://test.trusted-site.com'],
    credentials: true
  }
};

const currentConfig = corsConfig[process.env.NODE_ENV];
app.use(cors(currentConfig));
```

### 3. Logging and Monitoring
```javascript
const corsLogger = (req, res, next) => {
  const origin = req.header('Origin');
  
  if (origin) {
    console.log({
      timestamp: new Date(),
      origin,
      method: req.method,
      path: req.path,
      allowed: isAllowedOrigin(origin)
    });
  }
  
  next();
};

app.use(corsLogger);
```

## Emergency Response

### If Compromised

1. Immediate Actions:
```plaintext
1. Disable CORS temporarily
2. Review access logs
3. Update origin whitelist
4. Rotate security credentials
5. Notify affected users
```

2. Prevention Measures:
```javascript
// Implement rate limiting
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use('/api/', limiter);

// Monitor suspicious patterns
const monitor = (req, res, next) => {
  const suspicious = checkSuspiciousPatterns(req);
  if (suspicious) {
    notifySecurityTeam(req);
  }
  next();
};

app.use(monitor);
```

## Additional Resources
- [OWASP CORS Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client_Side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [MDN CORS Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [W3C CORS Specification](https://www.w3.org/TR/cors/)

## Contributing
Feel free to contribute by:
1. Reporting security issues
2. Suggesting improvements
3. Adding new implementations
4. Improving documentation

## License
MIT License

## Disclaimer
This guide is for educational purposes only. Always follow security best practices and applicable regulations in your jurisdiction.
