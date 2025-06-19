using System.ComponentModel.DataAnnotations;

namespace subscription_mgmt_api.DTOs
{
    /// <summary>
    /// Data transfer object for user login requests
    /// </summary>
    public class LoginRequest
    {
        /// <summary>
        /// User's email address
        /// </summary>
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// User's password
        /// </summary>
        [Required]
        [MinLength(6)]
        public string Password { get; set; } = string.Empty;
    }

    /// <summary>
    /// Data transfer object for user registration requests
    /// </summary>
    public class RegisterRequest
    {
        /// <summary>
        /// User's email address
        /// </summary>
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// User's full name
        /// </summary>
        [Required]
        [MaxLength(100)]
        public string FullName { get; set; } = string.Empty;

        /// <summary>
        /// User's password (will be hashed before storage)
        /// </summary>
        [Required]
        [MinLength(6)]
        public string Password { get; set; } = string.Empty;

        /// <summary>
        /// Password confirmation to ensure accuracy
        /// </summary>
        [Required]
        [Compare(nameof(Password), ErrorMessage = "Passwords do not match")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    /// <summary>
    /// Data transfer object for authentication responses
    /// </summary>
    public class AuthResponse
    {
        /// <summary>
        /// JWT access token for API authentication
        /// </summary>
        public string AccessToken { get; set; } = string.Empty;

        /// <summary>
        /// JWT refresh token for obtaining new access tokens
        /// </summary>
        public string RefreshToken { get; set; } = string.Empty;

        /// <summary>
        /// Token expiration time in seconds
        /// </summary>
        public int ExpiresIn { get; set; }

        /// <summary>
        /// Type of token (usually "Bearer")
        /// </summary>
        public string TokenType { get; set; } = "Bearer";

        /// <summary>
        /// User information (without sensitive data)
        /// </summary>
        public UserDto User { get; set; } = new UserDto();
    }

    /// <summary>
    /// Data transfer object for user information in responses
    /// </summary>
    public class UserDto
    {
        /// <summary>
        /// Unique identifier for the user
        /// </summary>
        public Guid Id { get; set; }

        /// <summary>
        /// User's email address
        /// </summary>
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// User's full name
        /// </summary>
        public string FullName { get; set; } = string.Empty;

        /// <summary>
        /// User's role in the system
        /// </summary>
        public string Role { get; set; } = string.Empty;
    }

    /// <summary>
    /// Data transfer object for refresh token requests
    /// </summary>
    public class RefreshTokenRequest
    {
        /// <summary>
        /// JWT refresh token
        /// </summary>
        [Required]
        public string RefreshToken { get; set; } = string.Empty;
    }
} 