using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;
using System.Linq.Expressions;
using UserManagement.Api.Models;

namespace UserManagement.Api.Services
{
    public class EmailService : IEmailService
    {
        private readonly EmailConfiguration _emailConfiguration;
        public EmailService(IOptions<EmailConfiguration> emailConfiguration)
        {
            _emailConfiguration = emailConfiguration.Value;
        }

        public void SendEmail(EmailMessage emailMessage)
        {
            try
            {
                var mimeMessage = GetMimeMessage(emailMessage);
                using (var client = new SmtpClient())
                {
                    client.Connect(_emailConfiguration.ServerAddress, _emailConfiguration.Port, MailKit.Security.SecureSocketOptions.StartTls);
                    client.Authenticate(_emailConfiguration.UserName, _emailConfiguration.Password);
                    client.Send(mimeMessage);
                }
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        private MimeMessage GetMimeMessage(EmailMessage emailMessage)
        {
            var mimeMessage = new MimeMessage();
            mimeMessage.From.Add(new MailboxAddress("User Management Team", _emailConfiguration.From));
            mimeMessage.To.AddRange(emailMessage.To);
            mimeMessage.Subject = emailMessage.Subject;
            mimeMessage.Body = new TextPart(MimeKit.Text.TextFormat.Text) { Text = emailMessage.Content };

            return mimeMessage;
        }
    }
}
