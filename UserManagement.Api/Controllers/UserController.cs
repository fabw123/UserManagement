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
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
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
            var users = _userService.GetUsers();
            return Ok(users);
        }

        [HttpPost]
        public async Task<IActionResult> CreateUser([FromBody]RegisterUser registerUser) 
        {
            var result = await _userService.CreateUser(registerUser);
            if (result.Succeeded)
            {
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
            var result = await _userService.LoginUser(loginUser);
            return StatusCode(result.StatusCode, result.Value);
        }

        [HttpPost("loginotp")]
        public async Task<IActionResult> LoginUserOtp(string userName,string loginCode)
        {
            var result = await _userService.LoginUserOtp(userName, loginCode);
            return StatusCode(result.StatusCode,result.Value);
        }

        [HttpPost("role")]
        public async Task<IActionResult> BindUserToRole([FromBody] BindUserRole bindUserRole)
        {
            var result = await _userService.BindUserToRole(bindUserRole);
            return StatusCode(result.StatusCode,result.Value);
        }

        [HttpGet("confirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var result = await _userService.ConfirmEmail(token, email);
            return StatusCode(result.StatusCode, result.Value);
        }

        [Authorize]
        [HttpPost("password/reset/request")]
        public async Task<IActionResult> ResetPasswordRequest(string email)
        {
            var result = await _userService.ResetPasswordRequest(email);
            return StatusCode(result.StatusCode, result.Value);
        }

        [Authorize]
        [HttpGet("password/reset")]
        public async Task<IActionResult> ResetPassword(string email, string token)
        {
            return Ok(new {email = email, token = token});
        }

        [Authorize]
        [HttpPost("password/reset")]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var result = await _userService.ResetPassword(resetPassword);
            return StatusCode(result.StatusCode, result.Value); 
        }

    }
}
