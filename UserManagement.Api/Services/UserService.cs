using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Asn1.Ocsp;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Web;
using UserManagement.Api.Models;
using UserManagement.Api.Models.Configuration;
using UserManagement.Api.Models.Requests;

namespace UserManagement.Api.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        private readonly IEmailService _emailService;
        private readonly ILogger<UserService> _logger;

        private readonly SystemConfiguration _systemConfiguration;
        private readonly JwtConfiguration _jwtConfiguration;

        public UserService(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailService emailService,
            IOptions<SystemConfiguration> systemConfiguration,
            IOptions<JwtConfiguration> jwtConfiguration,
            ILogger<UserService> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _emailService = emailService;
            _systemConfiguration = systemConfiguration.Value;
            _jwtConfiguration = jwtConfiguration.Value;
            _logger = logger;
        }

        public IEnumerable<UserResponse> GetUsers()
        {
            var users = _userManager.Users.ToList();
            var response = users.Select(x => (UserResponse)x).ToList();
            return response;
        }

        public async Task<IdentityResult> CreateUser(RegisterUser registerUser)
        {
            var user = (ApplicationUser)registerUser;
            var result = await _userManager.CreateAsync(user, registerUser.Password);
            if (result.Succeeded)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var tokenEncoded = HttpUtility.UrlEncode(token);
                var confirmationLink = $"{_systemConfiguration.ApiUrl}/user/confirmEmail?token={tokenEncoded}&email={user.Email}";
                var messageContent = $"Hello,\n You created an account in our system, please confirm your account through this link\n {confirmationLink} \n Regards, User Management Team";
                var message = new EmailMessage("User Management - Confirmation Email", messageContent, new List<string> { user.Email });
                _emailService.SendEmail(message);
            }
            return result;
        }

        public async Task<StatusResult> LoginUser(LoginUser loginUser)
        {
            var user = await _userManager.FindByNameAsync(loginUser.UserName);
            if (user is null || !(await _userManager.CheckPasswordAsync(user, loginUser.Password)))
            {
                _logger.LogWarning("Login failed for user {userName}", loginUser.UserName);
                return new StatusResult(StatusCodes.Status404NotFound, new { Message = $"Login failed. please check username and password" });
            }

            if (user.TwoFactorEnabled)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginUser.Password, false, true);
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                var messageContent = $"Hello,\n Plase use the following code to login in the system\n {token} \n Regards, User Management Team";
                var message = new EmailMessage("User Management - Confirmation Code", messageContent, user.Email);
                _emailService.SendEmail(message);

                _logger.LogInformation("Email with Login code was sent to {email}", user.Email);
                return new StatusResult(StatusCodes.Status200OK, new { Message = $"Login successfull. We have sent an email to {user.Email}" });
            }

            _logger.LogWarning("The user {userName} logged in without OTP", loginUser.UserName);
            var jwtToken = await GetToken(user);
            return new StatusResult(StatusCodes.Status200OK, new
            {
                Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                ExpirationDate = jwtToken.ValidTo
            });
        }

        public async Task<StatusResult> LoginUserOtp(string userName, string loginCode)
        {
            var user = await _userManager.FindByNameAsync(userName);
            var signin = await _signInManager.TwoFactorSignInAsync("Email", loginCode, false, false);
            if (signin.Succeeded && user is not null)
            {
                var jwtToken = await GetToken(user);
                _logger.LogInformation("User {userName} has been logged in", userName);
                return new StatusResult(StatusCodes.Status200OK, new
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    ExpirationDate = jwtToken.ValidTo
                });

            }
            return new StatusResult(StatusCodes.Status401Unauthorized, new { Message = "User name or Password incorrect" });
        }

        public async Task<StatusResult> BindUserToRole(BindUserRole bindUserRole)
        {
            var user = await _userManager.FindByNameAsync(bindUserRole.UserName);
            if (user is null)
            {
                return new StatusResult(StatusCodes.Status404NotFound, new { Message = $"User {bindUserRole.UserName} does not exist" });
            }

            var role = await _roleManager.FindByNameAsync(bindUserRole.RoleName);
            if (role is null)
            {
                return new StatusResult(StatusCodes.Status404NotFound, new { Message = $"Role {bindUserRole.RoleName} does not exist" });
            }

            var result = await _userManager.AddToRoleAsync(user, bindUserRole.RoleName);
            if (result.Succeeded)
            {
                _logger.LogInformation("User {userName} has been assigned to the role {role}", bindUserRole.UserName, bindUserRole.RoleName);
                return new StatusResult(StatusCodes.Status200OK, new { Message = $"User {bindUserRole.UserName}  has been associated to role {bindUserRole.RoleName}" });
            }

            
            return new StatusResult(StatusCodes.Status500InternalServerError,
                new { Message = "Error creating the user", Errors = result.Errors });
        }

        public async Task<StatusResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                return new StatusResult(StatusCodes.Status404NotFound, new { Message = $"User email not found: {email}" });
            }
            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return new StatusResult(StatusCodes.Status200OK, new { Message = "User Email was confirmed" });
            }
            return new StatusResult(StatusCodes.Status500InternalServerError, new { Message = "Error confirming the user ", Errors = result.Errors });
        }

        public async Task<StatusResult> ResetPasswordRequest(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                return new StatusResult(StatusCodes.Status404NotFound, new { Message = $"email {email} was not found" });
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var tokenEncoded = HttpUtility.UrlEncode(token);
            var link = $"{_systemConfiguration.ApiUrl}/user/password/forgot?token={tokenEncoded}&email={user.Email}";
            var messageContent = $"Hello,\n Please, use the following link to change your password:\n {link} \n Regards, User Management Team";
            var message = new EmailMessage("User Management - Password Reset Request", messageContent, user.Email);
            _emailService.SendEmail(message);

            return new StatusResult(StatusCodes.Status200OK, new { Message = $"Request succeded. An email have been sent to {user.Email} to continue the process" });
        }

        public async Task<StatusResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user is null)
            {
                return new StatusResult(StatusCodes.Status404NotFound, new { Message = $"email {resetPassword.Email} was not found" });
            }

            var result = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
            if (result.Succeeded)
            {
                return new StatusResult(StatusCodes.Status200OK, new { Message = "Password have been updated" });
            }

            return new StatusResult(StatusCodes.Status500InternalServerError, new
            {
                Message = $"Error changing the password for {resetPassword.Email}",
                Errors = result.Errors
            });
        }

        private async Task<JwtSecurityToken> GetToken(ApplicationUser user)
        {
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var authSingingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfiguration.Secret));
            var token = new JwtSecurityToken(
                issuer: _jwtConfiguration.Issuer,
                audience: _jwtConfiguration.Audience,
                claims: authClaims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: new SigningCredentials(authSingingKey, SecurityAlgorithms.HmacSha256));

            return token;
        }


    }
}
