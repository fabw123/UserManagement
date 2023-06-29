using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using UserManagement.Api.Models;
using UserManagement.Api.Services;

namespace UserManagement.Api.Controllers
{

    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailService _emailService;
        public UserController(UserManager<ApplicationUser> userManager, 
            RoleManager<IdentityRole> roleManager, 
            IEmailService emailService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _emailService = emailService;
        }

        [HttpGet("Status")]
        public IActionResult Index()
        {
            return Ok("Sistem is OK!");
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

        private async Task SendVerificationEmail(ApplicationUser user)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = Url.Action(nameof(ConfirmEmail), "User", new {Token = token, Email = user.Email}, Request.Scheme);
            var messageContent = $"Hello,\n You created an account in our system, please confirm your account through this link\n {confirmationLink} \n Regards, User Management Team";
            var message = new EmailMessage("User Management - Confirmation Email", messageContent, new List<string> { user.Email });
            _emailService.SendEmail(message);
        }

        [HttpPost("email/{keyValue}")]
        public IActionResult TestEmail(string keyValue)
        {
            var message = new EmailMessage("Email Test",
                $"This is the content for email test: {keyValue}",
                new List<string>() { "fabwpp@hotmail.com" });
            _emailService.SendEmail(message);

            return Ok("Email Sent successfully");
        }

    }
}
