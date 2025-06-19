using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using subscription_mgmt_api.Configuration;
using subscription_mgmt_api.DTOs;
using subscription_mgmt_api.Models;

namespace subscription_mgmt_api.Services
{
    /// <summary>
    /// Implementation of authentication service with JWT token management
    /// </summary>
    public class AuthService : IAuthService
    {
        private readonly JwtSettings _jwtSettings;
        private readonly Dictionary<string, string> _refreshTokens = new(); // In-memory storage for demo purposes
        private readonly Dictionary<string, User> _users = new(); // In-memory user storage for demo purposes

        /// <summary>
        /// Initializes a new instance of the AuthService
        /// </summary>
        /// <param name="jwtSettings">JWT configuration settings</param>
        public AuthService(JwtSettings jwtSettings)
        {
            _jwtSettings = jwtSettings;
            InitializeDemoUsers(); // Initialize with demo users for testing
        }

        /// <summary>
        /// Authenticates a user with email and password
        /// </summary>
        /// <param name="loginRequest">Login credentials</param>
        /// <returns>Authentication response with tokens</returns>
        public async Task<AuthResponse> LoginAsync(LoginRequest loginRequest)
        {
            // Simulate async operation
            await Task.Delay(1);

            // Find user by email
            User? user = _users.Values.FirstOrDefault(u => u.Email.Equals(loginRequest.Email, StringComparison.OrdinalIgnoreCase));
            
            if (user == null)
            {
                throw new UnauthorizedAccessException("Invalid email or password");
            }

            // Verify password
            if (!VerifyPassword(loginRequest.Password, user.PasswordHash))
            {
                throw new UnauthorizedAccessException("Invalid email or password");
            }

            // Check if user is active
            if (!user.IsActive)
            {
                throw new UnauthorizedAccessException("User account is deactivated");
            }

            // Generate tokens
            string accessToken = GenerateAccessToken(user);
            string refreshToken = GenerateRefreshToken();

            // Store refresh token
            _refreshTokens[refreshToken] = user.Id.ToString();

            // Create response
            AuthResponse authResponse = new AuthResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresIn = _jwtSettings.AccessTokenExpirationMinutes * 60,
                TokenType = "Bearer",
                User = new UserDto
                {
                    Id = user.Id,
                    Email = user.Email,
                    FullName = user.FullName,
                    Role = user.Role
                }
            };

            return authResponse;
        }

        /// <summary>
        /// Registers a new user
        /// </summary>
        /// <param name="registerRequest">User registration data</param>
        /// <returns>Authentication response with tokens</returns>
        public async Task<AuthResponse> RegisterAsync(RegisterRequest registerRequest)
        {
            // Simulate async operation
            await Task.Delay(1);

            // Check if user already exists
            if (_users.Values.Any(u => u.Email.Equals(registerRequest.Email, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException("User with this email already exists");
            }

            // Create new user
            User newUser = new User
            {
                Id = Guid.NewGuid(),
                Email = registerRequest.Email,
                FullName = registerRequest.FullName,
                PasswordHash = HashPassword(registerRequest.Password),
                Role = "User", // Default role
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            // Add user to storage
            _users[newUser.Id.ToString()] = newUser;

            // Generate tokens
            string accessToken = GenerateAccessToken(newUser);
            string refreshToken = GenerateRefreshToken();

            // Store refresh token
            _refreshTokens[refreshToken] = newUser.Id.ToString();

            // Create response
            AuthResponse authResponse = new AuthResponse
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresIn = _jwtSettings.AccessTokenExpirationMinutes * 60,
                TokenType = "Bearer",
                User = new UserDto
                {
                    Id = newUser.Id,
                    Email = newUser.Email,
                    FullName = newUser.FullName,
                    Role = newUser.Role
                }
            };

            return authResponse;
        }

        /// <summary>
        /// Refreshes an access token using a refresh token
        /// </summary>
        /// <param name="refreshTokenRequest">Refresh token request</param>
        /// <returns>New authentication response with tokens</returns>
        public async Task<AuthResponse> RefreshTokenAsync(RefreshTokenRequest refreshTokenRequest)
        {
            // Simulate async operation
            await Task.Delay(1);

            // Validate refresh token
            if (!_refreshTokens.TryGetValue(refreshTokenRequest.RefreshToken, out string? userId))
            {
                throw new UnauthorizedAccessException("Invalid refresh token");
            }

            // Get user
            if (!_users.TryGetValue(userId, out User? user))
            {
                throw new UnauthorizedAccessException("User not found");
            }

            // Check if user is active
            if (!user.IsActive)
            {
                throw new UnauthorizedAccessException("User account is deactivated");
            }

            // Generate new tokens
            string newAccessToken = GenerateAccessToken(user);
            string newRefreshToken = GenerateRefreshToken();

            // Remove old refresh token and add new one
            _refreshTokens.Remove(refreshTokenRequest.RefreshToken);
            _refreshTokens[newRefreshToken] = user.Id.ToString();

            // Create response
            AuthResponse authResponse = new AuthResponse
            {
                AccessToken = newAccessToken,
                RefreshToken = newRefreshToken,
                ExpiresIn = _jwtSettings.AccessTokenExpirationMinutes * 60,
                TokenType = "Bearer",
                User = new UserDto
                {
                    Id = user.Id,
                    Email = user.Email,
                    FullName = user.FullName,
                    Role = user.Role
                }
            };

            return authResponse;
        }

        /// <summary>
        /// Validates a JWT token and returns user information
        /// </summary>
        /// <param name="token">JWT token to validate</param>
        /// <returns>User information if token is valid</returns>
        public async Task<UserDto?> ValidateTokenAsync(string token)
        {
            // Simulate async operation
            await Task.Delay(1);

            try
            {
                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                byte[] key = Encoding.ASCII.GetBytes(_jwtSettings.SecretKey);

                TokenValidationParameters validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _jwtSettings.Issuer,
                    ValidateAudience = true,
                    ValidAudience = _jwtSettings.Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                ClaimsPrincipal principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

                // Extract user ID from claims
                string? userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId) || !_users.TryGetValue(userId, out User? user))
                {
                    return null;
                }

                // Check if user is active
                if (!user.IsActive)
                {
                    return null;
                }

                return new UserDto
                {
                    Id = user.Id,
                    Email = user.Email,
                    FullName = user.FullName,
                    Role = user.Role
                };
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Revokes a refresh token
        /// </summary>
        /// <param name="refreshToken">Refresh token to revoke</param>
        /// <returns>True if token was successfully revoked</returns>
        public async Task<bool> RevokeRefreshTokenAsync(string refreshToken)
        {
            // Simulate async operation
            await Task.Delay(1);

            return _refreshTokens.Remove(refreshToken);
        }

        /// <summary>
        /// Generates a JWT access token for a user
        /// </summary>
        /// <param name="user">User for whom to generate the token</param>
        /// <returns>JWT access token</returns>
        private string GenerateAccessToken(User user)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            byte[] key = Encoding.ASCII.GetBytes(_jwtSettings.SecretKey);

            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Name, user.FullName),
                    new Claim(ClaimTypes.Role, user.Role)
                }),
                Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
                Issuer = _jwtSettings.Issuer,
                Audience = _jwtSettings.Audience,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            SecurityToken token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        /// <summary>
        /// Generates a cryptographically secure refresh token
        /// </summary>
        /// <returns>Refresh token string</returns>
        private string GenerateRefreshToken()
        {
            byte[] randomBytes = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return Convert.ToBase64String(randomBytes);
        }

        /// <summary>
        /// Hashes a password using BCrypt
        /// </summary>
        /// <param name="password">Plain text password</param>
        /// <returns>Hashed password</returns>
        private string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        /// <summary>
        /// Verifies a password against its hash
        /// </summary>
        /// <param name="password">Plain text password</param>
        /// <param name="hash">Hashed password</param>
        /// <returns>True if password matches hash</returns>
        private bool VerifyPassword(string password, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }

        /// <summary>
        /// Initializes demo users for testing purposes
        /// </summary>
        private void InitializeDemoUsers()
        {
            User adminUser = new User
            {
                Id = Guid.NewGuid(),
                Email = "admin@example.com",
                FullName = "Admin User",
                PasswordHash = HashPassword("admin123"),
                Role = "Admin",
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            User regularUser = new User
            {
                Id = Guid.NewGuid(),
                Email = "user@example.com",
                FullName = "Regular User",
                PasswordHash = HashPassword("user123"),
                Role = "User",
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _users[adminUser.Id.ToString()] = adminUser;
            _users[regularUser.Id.ToString()] = regularUser;
        }
    }
} 