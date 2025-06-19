using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using subscription_mgmt_api.DTOs;
using subscription_mgmt_api.Services;

namespace subscription_mgmt_api.Controllers
{
    /// <summary>
    /// Controller for handling authentication operations
    /// </summary>
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        /// <summary>
        /// Initializes a new instance of the AuthController
        /// </summary>
        /// <param name="authService">Authentication service dependency</param>
        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        /// <summary>
        /// Authenticates a user with email and password
        /// </summary>
        /// <param name="loginRequest">Login credentials</param>
        /// <returns>Authentication response with JWT tokens</returns>
        /// <response code="200">Successfully authenticated</response>
        /// <response code="400">Invalid request data</response>
        /// <response code="401">Invalid credentials</response>
        [HttpPost("login")]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest loginRequest)
        {
            try
            {
                AuthResponse authResponse = await _authService.LoginAsync(loginRequest);
                return Ok(authResponse);
            }
            catch (UnauthorizedAccessException ex)
            {
                return Unauthorized(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Registers a new user account
        /// </summary>
        /// <param name="registerRequest">User registration data</param>
        /// <returns>Authentication response with JWT tokens</returns>
        /// <response code="200">Successfully registered</response>
        /// <response code="400">Invalid request data or user already exists</response>
        [HttpPost("register")]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult<AuthResponse>> Register([FromBody] RegisterRequest registerRequest)
        {
            try
            {
                AuthResponse authResponse = await _authService.RegisterAsync(registerRequest);
                return Ok(authResponse);
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Refreshes an access token using a refresh token
        /// </summary>
        /// <param name="refreshTokenRequest">Refresh token request</param>
        /// <returns>New authentication response with tokens</returns>
        /// <response code="200">Successfully refreshed token</response>
        /// <response code="400">Invalid request data</response>
        /// <response code="401">Invalid refresh token</response>
        [HttpPost("refresh")]
        [ProducesResponseType(typeof(AuthResponse), 200)]
        [ProducesResponseType(400)]
        [ProducesResponseType(401)]
        public async Task<ActionResult<AuthResponse>> RefreshToken([FromBody] RefreshTokenRequest refreshTokenRequest)
        {
            try
            {
                AuthResponse authResponse = await _authService.RefreshTokenAsync(refreshTokenRequest);
                return Ok(authResponse);
            }
            catch (UnauthorizedAccessException ex)
            {
                return Unauthorized(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Revokes a refresh token (logout)
        /// </summary>
        /// <param name="refreshTokenRequest">Refresh token to revoke</param>
        /// <returns>Success response</returns>
        /// <response code="200">Successfully logged out</response>
        /// <response code="400">Invalid request data</response>
        [HttpPost("logout")]
        [ProducesResponseType(200)]
        [ProducesResponseType(400)]
        public async Task<ActionResult> Logout([FromBody] RefreshTokenRequest refreshTokenRequest)
        {
            try
            {
                bool revoked = await _authService.RevokeRefreshTokenAsync(refreshTokenRequest.RefreshToken);
                if (revoked)
                {
                    return Ok(new { message = "Successfully logged out" });
                }
                else
                {
                    return BadRequest(new { message = "Invalid refresh token" });
                }
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }

        /// <summary>
        /// Validates the current user's token and returns user information
        /// </summary>
        /// <returns>User information</returns>
        /// <response code="200">Valid token, returns user info</response>
        /// <response code="401">Invalid or expired token</response>
        [HttpGet("me")]
        [Authorize]
        [ProducesResponseType(typeof(UserDto), 200)]
        [ProducesResponseType(401)]
        public async Task<ActionResult<UserDto>> GetCurrentUser()
        {
            try
            {
                // Extract token from Authorization header
                string? authHeader = Request.Headers["Authorization"].FirstOrDefault();
                if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized(new { message = "Invalid authorization header" });
                }

                string token = authHeader.Substring("Bearer ".Length);
                UserDto? user = await _authService.ValidateTokenAsync(token);

                if (user == null)
                {
                    return Unauthorized(new { message = "Invalid or expired token" });
                }

                return Ok(user);
            }
            catch (Exception ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
    }
} 