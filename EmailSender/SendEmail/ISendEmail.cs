using MimeKit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EmailSender.SendEmail
{
    public interface ISendEmail
    {
        Task<bool> SendVerificationEmailAsync(string email, string body);
        public  Task<bool> SendAlertEmailAsync(string email, string body);
        public  Task<bool> SendEmailAsync(string email, MimeMessage message);

        public  Task<bool> test(string email);
    }
}
