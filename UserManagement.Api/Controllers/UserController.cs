using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using UserManagement.Api.Models;
using UserManagement.Api.Models.Requests;
using UserManagement.Api.Services;

namespace UserManagement.Api.Controllers
{

    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailService _emailService;
        private readonly JwtConfiguration _jwtConfiguration;
        public UserController(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IEmailService emailService,
            IOptions<JwtConfiguration> jwtConfiguration,
            SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
            _jwtConfiguration = jwtConfiguration.Value;
            _signInManager = signInManager;
        }

        [HttpGet("Status")]
        public IActionResult Index()
        {
            return Ok("Sistem is OK!");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet]
        public IActionResult GetUsers()
        {
            var users = _userManager.Users.ToList();
            var response = users.Select(x => (UserResponse)x).ToList();
            return Ok(response);
        }

        [HttpPost("user")]
        public async Task<IActionResult> CreateUser([FromBody]RegisterUser registerUser) 
        {
            var userIdentity = new ApplicationUser()
            {
                FirstName = registerUser.FirstName,
                LastName = registerUser.LastName,
                BirthDate = registerUser.BirthDate,
                UserName = registerUser.UserName,
                Email = registerUser.Email,
                TwoFactorEnabled = true,
                ConcurrencyStamp = Guid.NewGuid().ToString()
            };

            var result = await _userManager.CreateAsync(userIdentity, registerUser.Password);
            if (result.Succeeded)
            {
                await SendVerificationEmail(userIdentity);

                return StatusCode(StatusCodes.Status200OK,
                    new { Message = "User created successfully" });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new { Message = "Error creating the user", Errors = result.Errors });
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> LoginUser([FromBody] LoginUser loginUser)
        {
            var user = await _userManager.FindByNameAsync(loginUser.UserName);
            if (user is null || !(await _userManager.CheckPasswordAsync(user, loginUser.Password)))
            {
                return StatusCode(StatusCodes.Status401Unauthorized,
                    new { Message = "User name or Password incorrect" });
            }

            if (user.TwoFactorEnabled)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, loginUser.Password, false, true);
                await SendOTPEmail(user);

                return StatusCode(StatusCodes.Status200OK,
                    new { Message = $"Login successfull. We have sent an email to {user.Email}" });
            }


            var jwtToken = await GetToken(user);

            return Ok(new
            {
                Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                ExpirationDate = jwtToken.ValidTo
            });

        }

        [HttpPost("loginotp")]
        public async Task<IActionResult> LoginUserOtp(string userName,string loginCode)
        {
            var user = await _userManager.FindByNameAsync(userName);
            var signin = await _signInManager.TwoFactorSignInAsync("Email", loginCode, false, false);
            if (signin.Succeeded && user is not null)
            {
                var jwtToken = await GetToken(user);

                return Ok(new
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                    ExpirationDate = jwtToken.ValidTo
                });
            }
            return StatusCode(StatusCodes.Status401Unauthorized,
                    new { Message = "User name or Password incorrect" });
        }

        [HttpPost("user/role")]
        public async Task<IActionResult> BindUserToRole([FromBody] BindUserRole bindUserRole)
        {
            var user = await _userManager.FindByNameAsync(bindUserRole.UserName);
            if (user is null)
            {
                return StatusCode(StatusCodes.Status404NotFound,
                    new { Message = $"User {bindUserRole.UserName} does not exist" });
            }

            var role = await _roleManager.FindByNameAsync(bindUserRole.RoleName);
            if (role is null)
            {
                return StatusCode(StatusCodes.Status404NotFound,
                    new { Message = $"Role {bindUserRole.RoleName} does not exist" });
            }

            var result = await _userManager.AddToRoleAsync(user, bindUserRole.RoleName);
            if (result.Succeeded)
            {
                return StatusCode(StatusCodes.Status200OK,
                    new { Message = $"User {bindUserRole.UserName}  has been associated to role {bindUserRole.RoleName}" });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new { Message = "Error creating the user", Errors = result.Errors });
            }
        }

        [HttpGet("confirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                return StatusCode(StatusCodes.Status404NotFound, new { Message = $"User email not found: {email}" });
            }
            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return StatusCode(StatusCodes.Status200OK,
                    new { Message = "User Email was confirmed" });
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                    new { Message = "Error confirming the user ", Errors = result.Errors });
        }

        [Authorize]
        [HttpPost("password/reset")]
        public async Task<IActionResult> ResetPassword(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user is null)
            {
                return StatusCode(StatusCodes.Status404NotFound, new
                {
                    Message = $"email {email} was not found"
                });
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var link = Url.Action(nameof(ForgotPassword), "User", new { token, email = user.Email }, Request.Scheme);
            var messageContent = $"Hello,\n Please, use the following link to change your password:\n {link} \n Regards, User Management Team";
            var message = new EmailMessage("User Management - Password Reset Request", messageContent, user.Email);
            _emailService.SendEmail(message);

            return Ok(new { Message = $"Request succeded. An email have been sent to {user.Email} to continue the process" });

        }

        [Authorize]
        [HttpGet("password/forgot")]
        public async Task<IActionResult> ForgotPassword(string email, string token)
        {
            return Ok(new {email = email, token = token});
        }

        [Authorize]
        [HttpPost("password/forgot")]
        public async Task<IActionResult> ForgotPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user is null)
            {
                return StatusCode(StatusCodes.Status404NotFound, new
                {
                    Message = $"email {resetPassword.Email} was not found"
                });
            }

            var result = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
            if (result.Succeeded)
            {
                return Ok(new { Message = "Password have been updated" });
            }

            return StatusCode(StatusCodes.Status400BadRequest, new
            {
                Message = $"Error changing the password for {resetPassword.Email}",
                Errors = result.Errors
            });
        }


        private async Task SendVerificationEmail(ApplicationUser user)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = Url.Action(nameof(ConfirmEmail), "User", new {Token = token, Email = user.Email}, Request.Scheme);
            var messageContent = $"Hello,\n You created an account in our system, please confirm your account through this link\n {confirmationLink} \n Regards, User Management Team";
            var message = new EmailMessage("User Management - Confirmation Email", messageContent, new List<string> { user.Email });
            _emailService.SendEmail(message);
        }

        private async Task SendOTPEmail(ApplicationUser user)
        {
            var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
            var messageContent = $"Hello,\n Plase use the following code to login in the system\n {token} \n Regards, User Management Team";
            var message = new EmailMessage("User Management - Confirmation Code", messageContent, new List<string> { user.Email });
            _emailService.SendEmail(message);
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
