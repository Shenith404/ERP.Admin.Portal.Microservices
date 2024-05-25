using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using MimeKit.Text;
using System.Net.Mail;
using System.Net.Security;

namespace EmailSender.SendEmail
{
    public class SendEmail : ISendEmail
    {
        string userName = Environment.GetEnvironmentVariable("EMAIL_USER_NAME")!;
        string password = Environment.GetEnvironmentVariable("EMAIL_PASSWORD")!;
        public async Task<bool> SendVerificationEmailAsync(string email, string body)
        {

           
            MimeMessage message = new MimeMessage();
            message.From.Add(new MailboxAddress("ERP System Faculty of Engineering UoR", "comecprogramming@gmail.com"));
            message.To.Add(MailboxAddress.Parse(email));
            message.Subject = "Email Verification";

            // Use TextPart.Text to set the body content

            message.Body = new TextPart(TextFormat.Html)
            {
                Text = body
            };
            /*message.Body = new TextPart(TextFormat.Html)
            {

                Text = $"Click the following link to verify your email <a href='{verificationLink}'>clicking here</a>."
            };*/

            using (var smtpClient = new MailKit.Net.Smtp.SmtpClient())
            {
                try
                {
                    smtpClient.ServerCertificateValidationCallback = (sender, certificate, chain, errors) =>
                    {
                        // Customize the certificate validation logic here
                        if (errors == SslPolicyErrors.None)
                            return true;

                        // Check if the certificate matches the expected host name
                        string expectedHostName = "smtp.gmail.com";
                        return certificate.Subject.Contains(expectedHostName);
                    };

                    smtpClient.Connect("smtp.gmail.com", 587, SecureSocketOptions.StartTls);
                    Console.WriteLine($"Connected to ");

                    smtpClient.Authenticate(userName,password);
                    Console.WriteLine("Authenticated");

                    await smtpClient.SendAsync(message);
                    Console.WriteLine("Message sent");

                    return true;
                }
                catch (Exception ex)
                {
                    // Log the exception or handle it appropriately
                    Console.WriteLine($"Error: {ex}");
                    return false;
                }
                finally
                {
                    await smtpClient.DisconnectAsync(true);
                    Console.WriteLine("Disconnected");
                }
            }
        }
         public async Task<bool> SendEmailAsync(string email, MimeMessage message)
        {
            

            using (var smtpClient = new MailKit.Net.Smtp.SmtpClient())
            {
                try
                {
                    smtpClient.ServerCertificateValidationCallback = (sender, certificate, chain, errors) =>
                    {
                        // Customize the certificate validation logic here
                        if (errors == SslPolicyErrors.None)
                            return true;

                        // Check if the certificate matches the expected host name
                        string expectedHostName = "smtp.gmail.com";
                        return certificate.Subject.Contains(expectedHostName);
                    };

                    smtpClient.Connect("smtp.gmail.com", 587, SecureSocketOptions.StartTls);
                    Console.WriteLine($"Connected to ");

                    smtpClient.Authenticate(userName, password);
                    Console.WriteLine("Authenticated");

                    await smtpClient.SendAsync(message);
                    Console.WriteLine("Message sent");

                    return true;
                }
                catch (Exception ex)
                {
                    // Log the exception or handle it appropriately
                    Console.WriteLine($"Error: {ex}");
                    return false;
                }
                finally
                {
                    await smtpClient.DisconnectAsync(true);
                    Console.WriteLine("Disconnected");
                }
            }
        }

         public async Task<bool> SendAlertEmailAsync(string email, string body)
        {
           
            MimeMessage message = new MimeMessage();
            message.From.Add(new MailboxAddress("ERP System Faculty of Engineering UoR", "comecprogramming@gmail.com"));
            message.To.Add(MailboxAddress.Parse(email));
            message.Subject = "Alert";

            // Use TextPart.Text to set the body content
            message.Body = new TextPart(TextFormat.Text)
            {
                Text = body
            };
            

            using (var smtpClient = new MailKit.Net.Smtp.SmtpClient())
            {
                try
                {
                    smtpClient.ServerCertificateValidationCallback = (sender, certificate, chain, errors) =>
                    {
                        // Customize the certificate validation logic here
                        if (errors == SslPolicyErrors.None)
                            return true;

                        // Check if the certificate matches the expected host name
                        string expectedHostName = "smtp.gmail.com";
                        return certificate.Subject.Contains(expectedHostName);
                    };

                    smtpClient.Connect("smtp.gmail.com", 587, SecureSocketOptions.StartTls);
                    Console.WriteLine($"Connected to ");

                    smtpClient.Authenticate(userName, password);
                    Console.WriteLine("Authenticated");

                    await smtpClient.SendAsync(message);
                    Console.WriteLine("Message sent");

                    return true;
                }
                catch (Exception ex)
                {
                    // Log the exception or handle it appropriately
                    Console.WriteLine($"Error: {ex}");
                    return false;
                }
                finally
                {
                    await smtpClient.DisconnectAsync(true);
                    Console.WriteLine("Disconnected");
                }
            }
        }

           public async Task<bool> test(string email)
        {
            string MailBody = "<!DOCTYPE html>" +
                                "<html> " +
                                    "<body style=\"background -color:#ff7f26;text-align:center;\"> " +
                                    "<h1 style=\"color:#051a80;\">Welcome to Nehanth World</h1> " +
                                    "<h2 style=\"color:#fff;\">Please find the attached files.</h2> " +
                                    "<label style=\"color:orange;font-size:100px;border:5px dotted;border-radius:50px\">N</label> " +
                                    "</body> " +
                                "</html>";
            MailMessage message = new MailMessage(new MailAddress(userName, password), new MailAddress(email));
            message.Subject = "sub";
            message.Body = MailBody;
            message.IsBodyHtml = true;


            //Server Details
            System.Net.Mail.SmtpClient smtp = new System.Net.Mail.SmtpClient();
            
            smtp.Host = "smtp.office365.com";
            smtp.Port = 587;
            smtp.EnableSsl = true;
            smtp.DeliveryMethod = SmtpDeliveryMethod.Network;

            //Credentials
            System.Net.NetworkCredential credentials = new System.Net.NetworkCredential();
            credentials.UserName = userName;
            credentials.Password = password;
            smtp.UseDefaultCredentials = false;
            smtp.Credentials = credentials;

            smtp.Send(message);

            Console.WriteLine("sent");

            return true;
        }
            

        

    }
}
