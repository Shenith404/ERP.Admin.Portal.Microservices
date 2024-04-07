using EmailSender.Api.DTOs;
using EmailSender.SendEmail;
using Microsoft.AspNetCore.Mvc;

namespace EmailSender.Api.Controllers
{
    public class SendEmailController : ControllerBase
    {
    
        private readonly ISendEmail _sendEmail;
        public SendEmailController(ISendEmail sendEmail)
        {
            _sendEmail = sendEmail;
        }
        [HttpPost]
        [Route("SendEmail")]
        public async Task<IActionResult> SendEmail([FromBody] SendEmailResponseDTO sendEmailResponse)
        {
            if(ModelState.IsValid)
            {
                bool result =await _sendEmail.SendVerificationEmailAsync(sendEmailResponse.Email, sendEmailResponse.Body);
                if (result)
                {
                    return Ok(result);
                }
            }
            return Ok();
        }
    }
}
