# Subscription Management API

A C# ASP.NET Core Web API for subscription management with JWT authentication and authorization.

## Features

- 🔐 **JWT Authentication**: Secure token-based authentication
- 👤 **User Management**: User registration, login, and profile management
- 🔄 **Token Refresh**: Automatic token refresh mechanism
- 🛡️ **Password Security**: BCrypt password hashing
- 📚 **Swagger Documentation**: Interactive API documentation
- 🏗️ **Clean Architecture**: Well-structured folder organization

## Project Structure

```
src/
├── subscription-mgmt-api/
│   ├── Controllers/          # API controllers
│   ├── Models/              # Domain models
│   ├── DTOs/                # Data Transfer Objects
│   ├── Services/            # Business logic services
│   ├── Configuration/       # Configuration classes
│   ├── Extensions/          # Extension methods
│   ├── Middleware/          # Custom middleware
│   └── Data/                # Data access layer
tests/
└── subscription-mgmt-api.Tests/  # Unit tests
```

## Getting Started

### Prerequisites

- .NET 8.0 SDK
- Your preferred IDE (Visual Studio, VS Code, Rider)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd subscription-mgmt-api
```

2. Build the solution:
```bash
dotnet build subscription-mgmt-api.sln
```

3. Run the application:
```bash
dotnet run --project src/subscription-mgmt-api/subscription-mgmt-api.csproj
```

The API will be available at:
- **API**: http://localhost:5218
- **Swagger UI**: http://localhost:5218/swagger

## Authentication Endpoints

### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "fullName": "John Doe",
  "password": "password123",
  "confirmPassword": "password123"
}
```

### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

### Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

### Get Current User
```http
GET /api/auth/me
Authorization: Bearer your-access-token
```

### Logout
```http
POST /api/auth/logout
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

## Demo Users

The system comes with pre-configured demo users for testing:

| Email | Password | Role |
|-------|----------|------|
| admin@example.com | admin123 | Admin |
| user@example.com | user123 | User |

## Configuration

JWT settings can be configured in `appsettings.json`:

```json
{
  "JwtSettings": {
    "SecretKey": "your-super-secret-key-with-at-least-32-characters-for-jwt-signing",
    "Issuer": "subscription-mgmt-api",
    "Audience": "subscription-mgmt-api",
    "AccessTokenExpirationMinutes": 60,
    "RefreshTokenExpirationDays": 7
  }
}
```

## Security Features

- **JWT Tokens**: Secure token-based authentication
- **Password Hashing**: BCrypt for secure password storage
- **Token Refresh**: Automatic token renewal
- **Token Revocation**: Secure logout mechanism
- **Input Validation**: Comprehensive request validation
- **Error Handling**: Secure error responses

## Development

### Adding New Endpoints

1. Create a new controller in the `Controllers/` folder
2. Add the `[Authorize]` attribute for protected endpoints
3. Use dependency injection for services
4. Follow the established naming conventions

### Testing

Run the tests:
```bash
dotnet test
```

## API Documentation

Visit http://localhost:5218/swagger for interactive API documentation when the application is running.

## Contributing

1. Follow the established code style and naming conventions
2. Add comprehensive comments and documentation
3. Use meaningful variable names
4. Prefer explicit types over `var` where appropriate
5. Add unit tests for new features

## License

This project is licensed under the MIT License. 