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
        private readonly ILogger<EmailService> _logger;
        public EmailService(IOptions<EmailConfiguration> emailConfiguration, 
            ILogger<EmailService> logger)
        {
            _emailConfiguration = emailConfiguration.Value;
            _logger = logger;
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
                _logger.LogError("An exception ocurred trying to send the email to {email}: {ex}",emailMessage.To,ex);
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
