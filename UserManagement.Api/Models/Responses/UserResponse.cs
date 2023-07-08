namespace UserManagement.Api.Models
{
    public class UserResponse
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public bool IsLockout { get; set; }

        public static explicit operator UserResponse(ApplicationUser applicationUser)
        {
            return new UserResponse()
            {
                FirstName = applicationUser.FirstName,
                LastName = applicationUser.LastName,
                UserName = applicationUser.UserName,
                Email = applicationUser.Email,
                IsLockout = applicationUser.LockoutEnabled
            };
        }
    }
}
