using UserManagement.Web.Models;

namespace UserManagement.Web.Services
{
    public interface IUserService
    {
        Task<IEnumerable<UserDto>> GetUsers();
    }
}