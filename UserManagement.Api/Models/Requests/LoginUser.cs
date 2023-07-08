using System.ComponentModel.DataAnnotations;

namespace UserManagement.Api.Models
{
    public class LoginUser
    {
        [Required]
        public string UserName { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
