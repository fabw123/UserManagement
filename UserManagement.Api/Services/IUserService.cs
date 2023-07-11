using Microsoft.AspNetCore.Identity;
using UserManagement.Api.Models;
using UserManagement.Api.Models.Requests;

namespace UserManagement.Api.Services
{
    public interface IUserService
    {
        IEnumerable<UserResponse> GetUsers();
        Task<StatusResult> BindUserToRole(BindUserRole bindUserRole);
        Task<StatusResult> ConfirmEmail(string token, string email);
        Task<IdentityResult> CreateUser(RegisterUser registerUser);
        Task<StatusResult> LoginUser(LoginUser loginUser);
        Task<StatusResult> LoginUserOtp(string userName, string loginCode);
        Task<StatusResult> ResetPassword(ResetPassword resetPassword);
        Task<StatusResult> ResetPasswordRequest(string email);
    }
}