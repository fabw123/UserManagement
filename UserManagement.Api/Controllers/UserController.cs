using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using UserManagement.Api.Models;

namespace UserManagement.Api.Controllers
{

    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {

        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public UserController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
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

    }
}
