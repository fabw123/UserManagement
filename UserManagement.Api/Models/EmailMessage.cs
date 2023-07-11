using MimeKit;

namespace UserManagement.Api.Models
{
    public class EmailMessage
    {
        
        public string Subject { get; set; }
        
        public string Content { get; set; }

        public List<MailboxAddress> To { get; set; }

        public EmailMessage(string subject, string content, List<string> to)
        {
            Subject = subject;
            Content = content;
            To = new List<MailboxAddress>();
            To.AddRange(to.Select(x => new MailboxAddress("email", x)));
        }

        public EmailMessage(string subject, string content, string to) 
            : this(subject, content, new List<string> { to })
        {
            
        }
    }
}
