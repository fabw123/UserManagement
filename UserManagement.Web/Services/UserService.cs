using System.Net.Http.Json;
using UserManagement.Web.Models;

namespace UserManagement.Web.Services
{
    public class UserService : IUserService
    {
        private readonly HttpClient _httpClient;

        public UserService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<IEnumerable<UserDto>> GetUsers()
        {
            var result = await _httpClient.GetFromJsonAsync<IEnumerable<UserDto>>("User");
            return result;
        }
    }
}
