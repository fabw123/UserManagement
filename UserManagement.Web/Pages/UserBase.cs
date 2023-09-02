using Microsoft.AspNetCore.Components;
using UserManagement.Web.Models;
using UserManagement.Web.Services;

namespace UserManagement.Web.Pages
{
    public class UserBase: ComponentBase
    {
        [Inject]
        public IUserService UserService { get; set; }

        public IEnumerable<UserDto> Users { get; set; }

        protected override async Task OnInitializedAsync()
        {
            Users= await UserService.GetUsers();
        }
    }
}
