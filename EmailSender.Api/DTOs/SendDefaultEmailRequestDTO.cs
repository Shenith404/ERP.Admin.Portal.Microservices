using MimeKit;

namespace EmailSender.Api.DTOs
{
    public class SendDefaultEmailRequestDTO
    {
        public string Email { get; set; }
        public MimeMessage message { get; set; }
    }
}
