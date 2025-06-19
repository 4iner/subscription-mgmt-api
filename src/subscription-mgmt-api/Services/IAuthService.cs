using subscription_mgmt_api.DTOs;
using subscription_mgmt_api.Models;

namespace subscription_mgmt_api.Services
{
    /// <summary>
    /// Interface for authentication service operations
    /// </summary>
    public interface IAuthService
    {
        /// <summary>
        /// Authenticates a user with email and password
        /// </summary>
        /// <param name="loginRequest">Login credentials</param>
        /// <returns>Authentication response with tokens</returns>
        Task<AuthResponse> LoginAsync(LoginRequest loginRequest);

        /// <summary>
        /// Registers a new user
        /// </summary>
        /// <param name="registerRequest">User registration data</param>
        /// <returns>Authentication response with tokens</returns>
        Task<AuthResponse> RegisterAsync(RegisterRequest registerRequest);

        /// <summary>
        /// Refreshes an access token using a refresh token
        /// </summary>
        /// <param name="refreshTokenRequest">Refresh token request</param>
        /// <returns>New authentication response with tokens</returns>
        Task<AuthResponse> RefreshTokenAsync(RefreshTokenRequest refreshTokenRequest);

        /// <summary>
        /// Validates a JWT token and returns user information
        /// </summary>
        /// <param name="token">JWT token to validate</param>
        /// <returns>User information if token is valid</returns>
        Task<UserDto?> ValidateTokenAsync(string token);

        /// <summary>
        /// Revokes a refresh token
        /// </summary>
        /// <param name="refreshToken">Refresh token to revoke</param>
        /// <returns>True if token was successfully revoked</returns>
        Task<bool> RevokeRefreshTokenAsync(string refreshToken);
    }
} 