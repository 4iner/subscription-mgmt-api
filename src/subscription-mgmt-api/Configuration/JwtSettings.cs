namespace subscription_mgmt_api.Configuration
{
    /// <summary>
    /// Configuration settings for JWT authentication
    /// </summary>
    public class JwtSettings
    {
        /// <summary>
        /// Secret key used to sign JWT tokens (should be at least 32 characters)
        /// </summary>
        public string SecretKey { get; set; } = string.Empty;

        /// <summary>
        /// Issuer of the JWT token (usually your application name)
        /// </summary>
        public string Issuer { get; set; } = string.Empty;

        /// <summary>
        /// Audience of the JWT token (usually your application name)
        /// </summary>
        public string Audience { get; set; } = string.Empty;

        /// <summary>
        /// Access token expiration time in minutes
        /// </summary>
        public int AccessTokenExpirationMinutes { get; set; } = 60;

        /// <summary>
        /// Refresh token expiration time in days
        /// </summary>
        public int RefreshTokenExpirationDays { get; set; } = 7;
    }
} 