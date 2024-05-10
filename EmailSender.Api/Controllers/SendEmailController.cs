using EmailSender.Api.DTOs;
using EmailSender.SendEmail;
using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;

namespace EmailSender.Api.Controllers
{

    [Route("api/[controller]")]
    [ApiController]
    public class SendEmailController : ControllerBase
    {
    
        private readonly ISendEmail _sendEmail;
        public SendEmailController(ISendEmail sendEmail)
        {
            _sendEmail = sendEmail;
        }
        [HttpPost]
        [Route("SendVerificationEmail")]
        public async Task<IActionResult> SendVerificationEmail([FromBody] SendEmailRequestDTO sendEmailResponse)
        {
            if(ModelState.IsValid)
            {
               if(IsValidEmail(sendEmailResponse.Email))
                {
                    bool result = await _sendEmail.SendVerificationEmailAsync(sendEmailResponse.Email, sendEmailResponse.Body);
                    if (result)
                    {
                        return Ok(result);
                    }
                }

                return BadRequest("Email is Not valid");
            }
            return Ok();
        }


        [HttpPost]
        [Route("SendAlertEmailAsync")]
        public async Task<IActionResult> SendAlertEmailAsync([FromBody] SendEmailRequestDTO sendEmailResponse)
        {
            if(ModelState.IsValid)
            {
               if(IsValidEmail(sendEmailResponse.Email))
                {
                    bool result = await _sendEmail.SendAlertEmailAsync(sendEmailResponse.Email, sendEmailResponse.Body);
                    if (result)
                    {
                        return Ok(result);
                    }
                }

                return BadRequest("Email is Not valid");
            }
            return Ok();
        }

        [HttpPost]
        [Route("SendEmailAsync")]
        public async Task<IActionResult> SendEmailAsync([FromBody] SendDefaultEmailRequestDTO sendEmailResponse)
        {
            if(ModelState.IsValid)
            {
               if(IsValidEmail(sendEmailResponse.Email))
                {
                    bool result = await _sendEmail.SendEmailAsync(sendEmailResponse.Email, sendEmailResponse.message);
                    if (result)
                    {
                        return Ok(result);
                    }
                }

                return BadRequest("Email is Not valid");
            }
            return Ok();
        }


        //Check email is valid


        private  bool IsValidEmail(string email)
        {
            // Regular expression pattern for email validation
            string pattern = @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";

            // Create a Regex object with the pattern
            Regex regex = new Regex(pattern);

            // Check if the email matches the pattern
            return regex.IsMatch(email);
        }
    }
}
