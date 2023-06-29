using UserManagement.Api.Models;

namespace UserManagement.Api.Services
{
    public interface IEmailService
    {
        void SendEmail(EmailMessage emailMessage);
    }
}