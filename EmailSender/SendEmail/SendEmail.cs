﻿using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using MimeKit.Text;
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

            message.Body = new TextPart(TextFormat.Text)
            {
                Text = body
            };
            /*message.Body = new TextPart(TextFormat.Html)
            {

                Text = $"Click the following link to verify your email <a href='{verificationLink}'>clicking here</a>."
            };*/

            using (var smtpClient = new SmtpClient())
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
            

            using (var smtpClient = new SmtpClient())
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
            /*message.Body = new TextPart(TextFormat.Html)
            {

                Text = $"Click the following link to verify your email <a href='{verificationLink}'>clicking here</a>."
            };*/

            using (var smtpClient = new SmtpClient())
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


    }
}
