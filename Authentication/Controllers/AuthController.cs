using RandomAppApi.Authentication.Dtos;
using RandomAppApi.Authentication.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Numerics;

namespace RandomAppApi.Authentication.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly IConfiguration _configuration;


        public AuthController(UserManager<User> userManager, SignInManager<User> signInManager, IEmailSender emailSender, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _emailSender = emailSender;
            _configuration = configuration;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequestDto registerDto )
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new User { 
                UserName = registerDto.Username,
                Email = registerDto.Email,
                Elo = registerDto.Elo
            };

            var result = await _userManager.CreateAsync(user, registerDto.Password!);

            if (!result.Succeeded) 
            {
                return BadRequest(result.Errors.Select(e => e.Description));
            }

            await SendConfirmationEmail(user);

            return Ok("User registration succeded, a confirmation email has been send to your email.");
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail([FromQuery] ConfirmEmailRequestDto confirmEmailDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await _userManager.FindByEmailAsync(confirmEmailDto.Email);

            if (user == null || user.EmailConfirmed)
            {
                return BadRequest("Invalid request.");
            }

            string token = confirmEmailDto.Token;
            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                return Ok("Email confirmation succeded.");
            }

            return BadRequest(result.Errors.Select(e => e.Description));
        }

        [HttpPost("ResendConfirmEmail")]
        public async Task<IActionResult> ResendConfirmEmail([FromBody] ResendConfirmEmailRequestDto resendConfirmEmailDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await _userManager.FindByEmailAsync(resendConfirmEmailDto.Email);

            if (user == null || user.EmailConfirmed)
            {
                return BadRequest("Invalid request.");
            }

            await SendConfirmationEmail(user);

            return Ok("Resend confirmation email succeded, a confirmation email has been send to your email.");
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto loginRequestDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = await _userManager.FindByEmailAsync(loginRequestDto.Email);

            if (user != null) 
            {
                if (!await _userManager.CheckPasswordAsync(user, loginRequestDto.Password))
                {
                    await _userManager.AccessFailedAsync(user);
                    return BadRequest("Invalid credentials");
                }

                if (!user.EmailConfirmed)
                {
                    return BadRequest("Email is not confirmed.");
                }

                if (await _userManager.IsLockedOutAsync(user) && user.LockoutEnd > DateTime.Now )
                {
                    return BadRequest("Account is locked out.");
                }

                await _userManager.ResetAccessFailedCountAsync(user);

                var tokens = GenerateJwtTokens(user);

                await _userManager.SetAuthenticationTokenAsync(user, "Default", "refreshToken", tokens.RefreshToken);

                return Ok(tokens);
            }

            return BadRequest("Invalid credentials");
        }

        [HttpPost("Refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequestDto refreshRequestDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var tokenClaims = DecryptRefreshToken(refreshRequestDto.RefreshToken!);

            if ( tokenClaims == null)
            {
                return BadRequest("Invalid token claims.");
            }

            var tokenEmail = tokenClaims.FindFirstValue(ClaimTypes.Email);

            if (tokenEmail == null)
            {
                return BadRequest("Invalid token email.");
            }

            var user = await _userManager.FindByEmailAsync(tokenEmail);

            if (user == null)
            {
                return BadRequest("Invalid token.");
            }

            var storedRefreshToken = await _userManager.GetAuthenticationTokenAsync(user, "Default", "refreshToken");

            if (storedRefreshToken == null || storedRefreshToken.ToString() != refreshRequestDto.RefreshToken)
            {
                return BadRequest("Invalid token user");
            }

            await _userManager.RemoveAuthenticationTokenAsync(user, "Default", "refreshToken");

            var tokens = GenerateJwtTokens(user);

            await _userManager.SetAuthenticationTokenAsync(user, "Default", "refreshToken", tokens.RefreshToken);

            return Ok(tokens);
        }

        private LoginResponseDto GenerateJwtTokens(User user)
        {
            var accessTokenKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWTSettings:AccessTokenKey"]!));
            var refreshTokenKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWTSettings:RefreshTokenKey"]!));

            var accessTokenclaims = new[]
            {
                new Claim(ClaimTypes.Email, user.Email!),
                new Claim(ClaimTypes.Name, user.UserName!)
            };

            var refreshTokenclaims = new[]
            {
                new Claim(ClaimTypes.Email, user.Email!),
            };

            var accessToken = new JwtSecurityToken(

                issuer: _configuration["JWTSettings:Issuer"],
                audience: _configuration["JWTSettings:Audience"],
                expires: DateTime.Now.AddMinutes(30),
                claims: accessTokenclaims,
                signingCredentials: new SigningCredentials(accessTokenKey, SecurityAlgorithms.HmacSha512Signature)
            );

            var refreshToken = new JwtSecurityToken(

                issuer: _configuration["JWTSettings:Issuer"],
                audience: _configuration["JWTSettings:Audience"],
                expires: DateTime.Now.AddDays(7),
                claims: refreshTokenclaims,
                signingCredentials: new SigningCredentials(refreshTokenKey, SecurityAlgorithms.HmacSha512Signature)
            );

            return new LoginResponseDto
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(accessToken),
                RefreshToken = new JwtSecurityTokenHandler().WriteToken(refreshToken)
            };
        }

        private ClaimsPrincipal DecryptRefreshToken(string refreshToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _configuration["JWTSettings:Issuer"],
                ValidAudience = _configuration["JWTSettings:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWTSettings:RefreshTokenKey"]!))
            };

            var principal = tokenHandler.ValidateToken(refreshToken, parameters, out _);

            return principal;
        }

        private async Task SendConfirmationEmail(User user)
        {
            string token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            string email = user.Email!;
            string link = $"https://localhost:7039/api/auth/confirmEmail?Email={ email }&Token={ token }";
            string message = $"Please confirm your account by<a href = '{ link }'> clicking here </ a >.";

            await _emailSender.SendEmailAsync(email, "Email Confirmation", message);
        }
    }
}