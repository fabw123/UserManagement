using System.ComponentModel.DataAnnotations;

namespace UserManagement.Api.Models.Requests
{
    public class ResetPassword
    {
        [Required]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }

        [Required]
        [Compare("Password",ErrorMessage ="The passwords do not match")]
        public string ConfirmPassword { get; set; }

        [Required]
        public string Token { get; set; }
    }
}
