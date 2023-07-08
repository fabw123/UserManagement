namespace UserManagement.Api.Models
{
    public class JwtConfiguration
    {
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public string Secret { get; set; }
    }
}
