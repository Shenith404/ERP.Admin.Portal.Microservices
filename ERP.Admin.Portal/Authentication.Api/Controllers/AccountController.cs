using Authentication.Core.DTOs;
using Authentication.Core.Entity;
using Authentication.DataService.IConfiguration;
using Authentication.jwt;
using AutoMapper;
using EmailSender.SendEmail;
using ERP.Authentication.Core.DTOs;
using ERP.Authentication.Core.Entity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using Notification.Core.DTOs;
using Notification.Core.Entity;
using Notification.DataService.IRepository;
using Notification.DataService.Repository;
using System.Drawing.Printing;
using System.Text;
using System.Text.Encodings.Web;

namespace Authentication.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : BaseController
    {
        private readonly ISendEmail _sendEmail;
        public AccountController(IJwtTokenHandler jwtTokenHandler, UserManager<UserModel> userManager, IMapper mapper,ISendEmail sendEmail,IUnitOfWorks unitOfWorks) 
            : base(jwtTokenHandler, userManager, mapper, unitOfWorks)
        {
            _sendEmail = sendEmail;
        }


        //Login User
        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] AuthenticationRequestDTO authenticationRequest)
        {
            if(ModelState.IsValid)
            {
                

                //check user is exist
                var existing_user = await _userManager.FindByEmailAsync(authenticationRequest.UserName);
                if (existing_user == null)
                {
                    return Unauthorized(
                          new AuthenticationResponseDTO()
                          {
                              Message = "Username is not Exist"
                          });
                 }



                //check is user deleted
                if (existing_user.Status != 1)
                {
                    return Unauthorized(
                         new AuthenticationResponseDTO()
                         {
                             Message = "This user is Deleted"
                         });
                }

                //check is user Locked
                var isLocked = await _userManager.IsLockedOutAsync(existing_user);
                if (isLocked==true)
                {
                    return Unauthorized(
                         new AuthenticationResponseDTO()
                         {
                             IsLocked=true,
                             Message = "This user is Locked"
                         });
                }

                //check is user Email is conformed
                if (existing_user.EmailConfirmed ==false)
                {
                    return Unauthorized(
                         new AuthenticationResponseDTO()
                         {
                             EmailConfirmed = await _userManager.IsEmailConfirmedAsync(existing_user),
                             Message = "Your Email is not Confirmed"
                         });
                }

                // 2F verification
                if(existing_user.TwoFactorEnabled ==true) {

                    var sendResult= await Send2FAVerificationToUserAsync(existing_user);


                    if (sendResult)
                    {
                        return Unauthorized(
                         new AuthenticationResponseDTO()
                         {
                             Is2FAConfirmed = true,
                             Message = $"We have sent verification code to your  email *******{existing_user.Email!.Substring(4)}"
                         });
                    }else
                    {
                        throw new Exception();
                    }
                
                }



                //check password is match
                var isCorrect = await _userManager.CheckPasswordAsync(existing_user,authenticationRequest.Password);
                if (isCorrect==false)
                {
                    return Unauthorized(
                      new AuthenticationResponseDTO()
                      {
                          Message = "Password is Incorrect"
                      });
                }
                var result = await GenenarateAuthenticatinResponse(existing_user);

                return Ok(result);




            }

            return Unauthorized(
              new AuthenticationResponseDTO()
              {
                  Message = "Invalid User Credentials"
              });
        }

       
        
        
        //Register User
        //need to change
        [HttpPost]
        [Route("Create")]
        public async Task<IActionResult> Register([FromBody] AuthenticationRequestDTO authenticationRequest)
        {
            if (ModelState.IsValid)
            {


                var user_exist = await _userManager.FindByEmailAsync(authenticationRequest.UserName);


                //Check Email is already taken
                if (user_exist != null)
                {

                    //check added email is contain in deleted account
                    if (user_exist.Status != 1)
                    {
                        return BadRequest(
                             new AuthenticationResponseDTO()
                             {
                                 Message = "You cant user this email"
                             });
                    }

                    return BadRequest(
                        new AuthenticationResponseDTO()
                        {
                            Message = "Email is Already Exist"
                        });
                }

                //Create User

                var new_user = new UserModel()
                {
                    Email = authenticationRequest.UserName,
                    UserName = authenticationRequest.UserName,
                    Status = 1,
                    EmailConfirmed = false
                };

                var is_created = await _userManager.CreateAsync(new_user, authenticationRequest.Password);

                var get_created_user = await _userManager.FindByEmailAsync(authenticationRequest.UserName);


                // Add Default Role as Reguler

                // await _roleManager.CreateAsync(new IdentityRole("Reguler"));
                if (get_created_user != null)
                {
                    await _userManager.AddToRoleAsync(get_created_user!, "Reguler");
                }



                if (is_created.Succeeded && get_created_user != null)
                {

                  
                    var result = await SendConfirmationEmailAsync(get_created_user);

                    if (result)
                    {
                        return Ok("User Created Successful ,Check the email for comfirmation");
                    }
                    return Ok(false);

                 
                }
                return BadRequest(
                    new AuthenticationResponseDTO()
                    {
                        Message = "Server Error"
                    });
            }

            return BadRequest(
                new AuthenticationResponseDTO()
                {
                    Message = "Invalid User Credentials"
                });

        }




        [HttpGet]
        [Route("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            Console.WriteLine(code);
            if (userId == null || code == null)
            {
                Console.WriteLine("Invalid Email Confirm Url");
                return BadRequest("Invalid Email Confirm Url");
            }

            var user = await _userManager.FindByIdAsync(userId);


            if(user == null)
            {
                Console.WriteLine("Invalid Email ");

                return BadRequest("Invalid Email");
            }
            if (code != user.ConfirmationEmailLink) {
                Console.WriteLine("link is used");
                return BadRequest("This link has been used");
            
            }
            if(user.ConfirmationEmailLinkExpTime < DateTime.UtcNow)
            {
                Console.WriteLine("This link is expired");
                return BadRequest("This link is expired");
            }

            var decodedCode = Encoding.UTF8.GetString(Convert.FromBase64String(code));
            var reuslt = await _userManager.ConfirmEmailAsync(user, decodedCode);
            if (reuslt.Succeeded) {

                user.ConfirmationEmailLink = null;
                await _userManager.UpdateAsync(user);
                Console.WriteLine("Email Confrim is Successfull");
                return Ok("Email Confrim is Successfull");
            }
            else
            {
                Console.WriteLine($"Email Confrim not Successfull : {reuslt}");
                return BadRequest("Email Confrim not Successfull");
            }
            
        }

      
       
        
        [HttpPost("Security")]
        public async Task<IActionResult> ChangeSecurity([FromBody] LockOutDetailsInfoDTO lockOutDetailsInfo)
        {
            if(ModelState.IsValid) { 
                var exist_user = await _userManager.FindByEmailAsync(lockOutDetailsInfo.Email);

                if( exist_user != null)
                {
                   
                    var result = await _userManager.SetLockoutEnabledAsync(exist_user,lockOutDetailsInfo.LockoutEnable);
                    if(result.Succeeded) {
                        return Ok();
                    }

                }


            
            }

            return BadRequest();
        }



        [HttpPost]
        [Route("Request-RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenInfoDTO tokenInfoDTO)
        {
            if (ModelState.IsValid) {

                //check is token is valid
                var result = await _jwtTokenHandler.VerifyToken(tokenInfoDTO);

                if(result != null)
                {
                    return Ok(
                        result);
                }
                return BadRequest(
                    new AuthenticationResponseDTO
                    {
                        Message="Token Request is failed"
                    });
            }

            return BadRequest();
        }

        
        
        
        [HttpGet]
        [Route("Get-User-Details")]
        //[Authorize]
        public async Task<IActionResult> GetUserDetails()
        {
            var currentUser = await _userManager.GetUserAsync(HttpContext.User);
            if (currentUser != null)
            {
                var mappedUser =_mapper.Map<UserModelResponseDTO>(currentUser);
                return Ok(mappedUser);
            }
            return Unauthorized("Fetch user details is faild");
        }


       
        
        [HttpPost]
        [Route("2FAVerification")]
        public async Task<IActionResult> TwoFactorVerification([FromBody] TwoFAVerificatinRequestDTO twoFAVerificatinRequestDTO)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(twoFAVerificatinRequestDTO.Email);
                if (user == null)
                {
                    return BadRequest("User is Not exist");
                }
                if (user.TwoFactorAuthenticationCode != twoFAVerificatinRequestDTO.Code)
                {
                    return BadRequest("Invalid Code or This code has been used");
                }
                if (user.TwoFactorAuthenticationCodeExpTime < DateTime.UtcNow)
                {
                    return BadRequest("This code is Expired");
                }
                var result = await _userManager.VerifyTwoFactorTokenAsync(user,"Email",twoFAVerificatinRequestDTO.Code);
                if (result == true)
                {
                    user.TwoFactorAuthenticationCode = null;
                    await _userManager.UpdateAsync(user);

                    return Ok( await GenenarateAuthenticatinResponse(user));
                }
            }
            return BadRequest("Faild");
        }

       
        
        
        [HttpPost]
        [Route("Resend-2FAVerificationCode")]
        public async Task<IActionResult> Resend2FAVerificationCode([FromBody] string email)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(email);

                // Check user is valid
                if (user == null)
                {
                    return BadRequest("Email is not Valid");
                }
                
                //check user 2FA enabled
                if(user.TwoFactorEnabled ==false || user.Status == 0 || 
                    user.EmailConfirmed == false || await _userManager.IsLockedOutAsync(user))
                {
                    return BadRequest("Invalid");
                }

                var sendResult = await Send2FAVerificationToUserAsync(user);


                if (sendResult)
                {
                    return Unauthorized(
                     new AuthenticationResponseDTO()
                     {
                         Is2FAConfirmed = true,
                         Message = $"We have sent verification code to your  email *******{user.Email!.Substring(4)}"
                     });
                }
                else
                {
                    throw new Exception();
                }
            }

            return BadRequest("Faild");
        }


        
        
        [HttpPost]
        [Route("Resend-Confirmation-Email")]
        public async Task<IActionResult> ResendConfirmationEmail([FromBody] string email)
        {
            if (ModelState.IsValid) {
                var existing_user = await _userManager.FindByEmailAsync(email);
                if (existing_user == null)
                {
                    return BadRequest(
                          
                             "Username is not Exist"
                          );
                }


                //check is user deleted
                if (existing_user.Status != 1)
                {
                    return BadRequest(
                        
                            "This user is Deleted"
                         );
                }

                //check is user Locked
                var isLocked = await _userManager.IsLockedOutAsync(existing_user);
                if (isLocked == true)
                {
                    return BadRequest(
                             "This user is Locked"
                         );
                }

                //check is user Email is conformed
                if (existing_user.EmailConfirmed == false)
                {
                   var result = await SendConfirmationEmailAsync(existing_user);

                   return result ? Ok($"We have sent verification code to your  email *******{existing_user.Email!.Substring(4)}") 
                        : BadRequest("Something is wrong. Please try again!");
                }

            }
        
        
            return BadRequest();
        }


        
        
        [HttpPost]
        [Route("Update")]
        //[Authorize] should change
        public async Task<IActionResult> UpdateUser(UserModel user) {
            if (ModelState.IsValid)
            {
                var result =await _userManager.UpdateAsync(user);
                if (result.Succeeded)
                {
                    return Ok("Sucessfully Updated");
                }
                return BadRequest();
            }
            return BadRequest();

        
        }

        [HttpPost]
        [Route("Enable-2FA")]
        //[Authorize]

        public async Task<IActionResult> EnableTFA([FromBody] TFAEnableRequestDTO tFAEnableRequestDTO)
        {
            if (ModelState.IsValid) {
               var user = await _userManager.GetUserAsync(HttpContext.User);
              if (user == null)
                {
                    return BadRequest("User is null");
                }
                var checkPassword = await IsPasswordCorrectAsync(tFAEnableRequestDTO.Password,user!);
                if (checkPassword==false)
                {
                    return BadRequest("Incorrect Password");
                }

                var result = await _userManager.SetTwoFactorEnabledAsync(user, tFAEnableRequestDTO.IsEnable);

                if (result.Succeeded)
                {
                  return  tFAEnableRequestDTO.IsEnable ?  Ok("2FA is Enabled")
                        :Ok("2FA is Disabled");
                }

            
            }
            return BadRequest();
        }

        
        
        
        [HttpPost]
        [Route("ChangePassword")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDTO changePassword)
        {
            // Retrieve the current user
            var currentUser = await _userManager.GetUserAsync(HttpContext.User);

            // Ensure the current user exists and model state is valid
            if (currentUser == null || !ModelState.IsValid)
            {
                return BadRequest("Invalid request");
            }

            // Validate input parameters
            if (string.IsNullOrWhiteSpace(changePassword.NewPassword) || string.IsNullOrWhiteSpace(changePassword.OldPassword))
            {
                return BadRequest("New password or old password is missing");
            }

            // Check if the old password matches
            var isOldPasswordCorrect = await IsPasswordCorrectAsync(changePassword.OldPassword, currentUser);
            if (!isOldPasswordCorrect)
            {
                return BadRequest("The old password is incorrect");
            }

            // Change password
            var result = await _userManager.ChangePasswordAsync(currentUser, changePassword.OldPassword, changePassword.NewPassword);
            if (result.Succeeded)
            {
                return Ok("Password changed successfully");
            }

            // Handle password change failure
            var errorMessage = string.Join(", ", result.Errors.Select(error => error.Description));
            return BadRequest(errorMessage);
        }

        
        
        
        
        
        
        
        // Generate Authentication response

        private async Task<AuthenticationResponseDTO> GenenarateAuthenticatinResponse(UserModel existing_user)
        {

            //Get user Role from database

            var roles = await _userManager.GetRolesAsync(existing_user);


            //Generate token

            TokenRequestDTO tokenRequest = new TokenRequestDTO();
            tokenRequest.UserName = existing_user.UserName!;
            if (!roles.IsNullOrEmpty())
            {
                tokenRequest.Role = "Reguler";
            }
            tokenRequest.Role = roles[0];
            tokenRequest.UserId = existing_user.Id;



            var result = await _jwtTokenHandler.GenerateJwtToken(tokenRequest);

            await DetectNewDeviceLogin(existing_user);

            return
                new AuthenticationResponseDTO
                {
                    JwtToken = result!.JwtToken,
                    RefreshToken = result!.RefreshToken,
                    ExpiresIn = result.ExpiresIn,
                    UserName = result.UserName,
                    Message = "User Login Successfully",
                    IsLocked = await _userManager.IsLockedOutAsync(existing_user),
                    EmailConfirmed = await _userManager.IsEmailConfirmedAsync(existing_user),
                    Is2FAConfirmed = true

                };

        }

       
        
        
        // Check if the password is correct
        private async Task<bool> IsPasswordCorrectAsync(string password, UserModel user)
        {
            if (user != null)
            {
                return await _userManager.CheckPasswordAsync(user, password);
            }
            return false;
        }


        
        
        // send confirmatin email

        private async Task<bool> SendConfirmationEmailAsync(UserModel get_created_user)
        {
            // Create Confirmation Email token for created user
            var emailConfirmedToken = await _userManager.GenerateEmailConfirmationTokenAsync(get_created_user);

            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(emailConfirmedToken));

            // Store the encoded token in the database
            get_created_user.ConfirmationEmailLink = encodedToken;
            get_created_user.ConfirmationEmailLinkExpTime = DateTime.UtcNow.AddMinutes(2);
            await _userManager.UpdateAsync(get_created_user);

            // Create callback URL
            // https://localhost:7048/api/Account/ConfirmEmail?userId=31fe1e1c-1512-436b-b855-a483f66b5683&code=Q2ZESjhDbGFJZGRXVjdoSG13NHMwc1g3K0dBUnpnNTZpY0Zva2JkU3RMMy9EZXFBR0NwME5JZ3Z2RHJIbnNibE5iZnhZN3ZyOUE4OXBJVk43MFVwVC9mK2NBNE5VNVFPOVc5UDhoWTJ6Uyt0TmFzM2lxdUNwYWZwWjdFZ25sY3kzTjVFQUZuR1U3cldGNGx1Z1czUUJ1RUI4bTI2dUQzTHhYazJUWkFod0doZWVySC95WWVnb0N5N0RYamZjdHRBZnlVS1pwTzRWSStwTUc4TTQvL05MaFVYalZhV0tTQk1sNzFuMSswQ2ZKYlNGZDBjamNrMWtURGVkTEVoT3pUVUxkc2RaZz09
            var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = get_created_user.Id, code = encodedToken }, Request.Scheme);

            var emailBody = $"Please Confirm your email address <a href=\"{callbackUrl}\">Click link</a>";

            return await _sendEmail.SendVerificationEmailAsync(get_created_user.Email!, emailBody);
        }




        // send 2FA code via email
        private async Task<bool> Send2FAVerificationToUserAsync(UserModel existing_user)
        {
            var code = await _userManager.GenerateTwoFactorTokenAsync(existing_user, "Email");

            //Store the token in database
            existing_user.TwoFactorAuthenticationCode = code;
            Console.WriteLine(code);

            existing_user.TwoFactorAuthenticationCodeExpTime = DateTime.UtcNow.AddMinutes(10);
            var result =await _userManager.UpdateAsync(existing_user);
            if (result.Succeeded)
            {
                var body = $"Your Verification code is  {code}";

                var sendResult = await _sendEmail.SendVerificationEmailAsync(existing_user.Email!, body);

                return sendResult;
            }

            return false;

            
        }

       
        private async Task<UserDeviceInformation> StoreTheUserDataInformation(UserModel existing_user)
        {
            string userAgent = Request.Headers["User-Agent"];
            var details = UserAgentDetailsDTO.GetBrowser(userAgent);
            Console.WriteLine(userAgent);
            Console.WriteLine("Browser: " + details.BrowserName);
            Console.WriteLine("Browser Version: " + details.BrowserVersion);
            Console.WriteLine("Operating System: " + details.OperatingSystem);
            //Console.WriteLine("Device Type: " + details.DeviceType);

            UserDeviceInformation usrDeviceInformation = new UserDeviceInformation
            {
                UserAgentDetails = userAgent,
                Status = 1,
                IP = "fsdfds",
                UserId = new Guid(existing_user.Id),


            };

            await _unitOfWorks.UserDeviceInformations.Add(usrDeviceInformation);
            await _unitOfWorks.CompleteAsync();
            return usrDeviceInformation;
        }

        private async Task DetectNewDeviceLogin(UserModel existing_user)
        {
            string  ?userAgent = Request.Headers["User-Agent"];

            //Check whether device info in database
            var deviceInfo = await _unitOfWorks.UserDeviceInformations.Checkinfo(new Guid(existing_user.Id), userAgent);

            if(deviceInfo==false)
            {
                //save new info to data base

               var info =await StoreTheUserDataInformation(existing_user);
               var details = UserAgentDetailsDTO.GetBrowser(info.UserAgentDetails!);
                //send email new login detected

                string htmlBody = $"Dear User,\r\n\r\nWe want to inform you that a new device was detected logging into your account." +
                    $"Your account security is our top priority, and we take such events seriously." +
                    $"\r\n\r\nDetails:\r\n\r\nDate and Time: {DateTime.Now}" +
                    $"\r\nDevice: {details.BrowserName} {details.DeviceType} \r\nLocation: [Insert Location, if available]" +
                    $"\r\nAction Required:\r\n\r\nIf this login was authorized by you, you may disregard this message.";
               
                await _sendEmail.SendAlertEmailAsync(existing_user.UserName!, htmlBody);


              
            }

        }
        
        [HttpGet]
        [Route("test")]
        public async Task<IActionResult> Test()
        {
            
            return Ok ("Hello world, this is test authentication");
        }

    }

}
