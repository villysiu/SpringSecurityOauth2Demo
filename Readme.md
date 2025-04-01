In this tutorial, we are building a Spring boot REST API authenticated with Spring Security, OAuth2.0 and Jwt token.

## Summary ##
This application allows user to 
- sign up with email and password
- login with valid credentail
- login through Github authentication by OAuth 2.0
Upon successful authentication, either by email/password or Github, 
- the authenticated user will be persisted in teh SecurityContextHolder in Spring Security.
- a JWT token will be generated and stored in cookie which is automatically sent with every request within thwe same domain.
- The browser automatically includes this cookie in subsequent requests to the server (if it's within the same domain).
- in this way, we are not relying om the server as JWT token is stateless

