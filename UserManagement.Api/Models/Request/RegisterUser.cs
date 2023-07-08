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
    }
}
