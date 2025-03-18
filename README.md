# JWT Authentication System with 2FA (TOTP)
A secure JWT-based authentication system with Two-Factor Authentication (TOTP) using Google Authenticator.

# Tech Stack
Backend: Node.js, Express.js
Database: MongoDB (Mongoose)
Authentication: JWT, bcrypt, speakeasy (for TOTP)
Templating Engine: EJS

# Authentication Flow

-  User Registers → Redirects to /totp for 2FA setup
-  User Scans QR Code (Google Authenticator)
-  User Enters TOTP Code → Verified & saved in DB
-  User Logs In → If 2FA is enabled, they can freely login in with password
-  If User forgots password they can enter the TOTP Code and can reset the password 
-  Authenticated! 

# Security Measures
-  Passwords are hashed with bcrypt (10 salt rounds)
-  JWT tokens stored in HttpOnly cookies to prevent XSS
-  TOTP-based password reset (No email exploit risks)
