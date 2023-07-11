using System.ComponentModel.DataAnnotations;

namespace UserManagement.Api.Models
{
    public class RegisterUser
    {
        [Required]
        public string FirstName { get; set; }

        [Required]
        public string LastName { get; set; }
       
        [Required]
        public string UserName { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }

        public DateTime BirthDate { get; set; }

        public static explicit operator ApplicationUser(RegisterUser registerUser)
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
            return userIdentity;
        }
    }
}
