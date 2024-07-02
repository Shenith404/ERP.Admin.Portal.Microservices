using Authentication.Core.DTOs.Common;
using Authentication.Core.DTOs.Request;
using Authentication.Core.DTOs.Response;
using Authentication.Core.Entity;
using Authentication.DataService.IConfiguration;
using Authentication.jwt;
using AutoMapper;
using EmailSender.SendEmail;
using ERP.Authentication.Core.Entity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using Notification.Core.Entity;
using System.Net.Http;
using System.Text;
using static Org.BouncyCastle.Crypto.Engines.SM2Engine;


namespace Authentication.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : BaseController
    {
        private readonly ISendEmail _sendEmail;
        private readonly HttpClient _httpClient;

        public AccountController(IJwtTokenHandler jwtTokenHandler, UserManager<UserModel> userManager, IMapper mapper,ISendEmail sendEmail,IUnitOfWorks unitOfWorks,HttpClient httpClient) 
            : base(jwtTokenHandler, userManager, mapper, unitOfWorks)
        {
            _sendEmail = sendEmail;
            _httpClient = httpClient;
        }


        //Login User
        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] AuthenticationRequestDTO authenticationRequest )
        {

            if(ModelState.IsValid)
            {

                //check user is exist
                var existing_user = await _userManager.FindByEmailAsync(authenticationRequest.UserName);
                if (existing_user == null)
                {
                    return BadRequest(
                          new AuthenticationResponseDTO()
                          {
                              Message = "Username is not Exist"
                          });
                 }



                //check is user deleted
                if (existing_user.Status != 1)
                {
                    return BadRequest(
                         new AuthenticationResponseDTO()
                         {
                             Message = "This user is Deleted"
                         });
                }

                //check is user Locked
                var isLocked = await _userManager.IsLockedOutAsync(existing_user);
                if (isLocked==true)
                {
                    return BadRequest(
                         new AuthenticationResponseDTO()
                         {
                             IsLocked=true,
                             Message = "This user is Locked"
                         });
                }

                //check is user Email is conformed
                if (existing_user.EmailConfirmed ==false)
                {
                    return BadRequest(
                         new AuthenticationResponseDTO()
                         {
                             EmailConfirmed = await _userManager.IsEmailConfirmedAsync(existing_user),
                             Message = "Your Email is not Confirmed"
                         });
                }

             

                //check password is match
                var isCorrect = await _userManager.CheckPasswordAsync(existing_user,authenticationRequest.Password);
                if (isCorrect!=false)
                {

                    // 2F verification
                    if (existing_user.TwoFactorEnabled == true)
                    {

                        var sendResult = await Send2FAVerificationToUserAsync(existing_user);


                        try
                        {
                            if (sendResult)
                            {
                                return BadRequest(
                                 new AuthenticationResponseDTO()
                                 {
                                     Is2FAConfirmed = true,
                                     Message = $"We have sent verification code to your  email *******{existing_user.Email!.Substring(4)}"
                                 });
                            }
                            else
                            {
                                return BadRequest(
                                 new AuthenticationResponseDTO()
                                 {
                                    
                                     Is2FAConfirmed=true,
                                     Message = $"Please try again.Email Sendig is Fail"
                                 });
                            }

                        }
                        catch (Exception ex)
                        {
                            return BadRequest(
                                 new AuthenticationResponseDTO()
                                 {
                                     Message = $"Please try again {ex}"
                                 });
                        }

                    }



                    var result = await GenenarateAuthenticatinResponse(existing_user);

                    return Ok(result);
                   
                }

                // Add faild attempt
                await DetectInvalidLoginAttempts(false,existing_user);

                return BadRequest(
                     new AuthenticationResponseDTO()
                     {
                         Message = "Password is Incorrect"
                     });





            }

            return BadRequest(
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

                var get_created_user = await _userManager.FindByNameAsync(authenticationRequest.UserName);


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

                        NotificationModel notification = new NotificationModel
                        {

                            Title = "Welcome",
                            Content = "Welcome to ERP system Faculty of Engineering University of Ruhuna",
                            ReadStatus = false,
                            Type = NotificationType.Success,
                            AddedDate = DateTime.Now,
                            ReceiverId = new Guid(get_created_user.Id),
                            Priority = 0,
                            Link = null
                        };

                        var nResult = await _httpClient.PostAsJsonAsync("https://localhost:7295/api/Notification/Create", notification);
                        return Ok(new AuthenticationResponseDTO()
                        {
                            Message = "User Created Successful ,Check the email for comfirmation"
                        });
                       
                    }
                    return Ok("User Created Successful ,Fail to send Email");

                 
                }
                return BadRequest(
                    new AuthenticationResponseDTO()
                    {
                        Message = $"Can't Create: {is_created.Errors}"
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
                return Ok("Email Confirm is Successfull");
            }
            else
            {
                Console.WriteLine($"Email Confrim not Successfull : {reuslt}");
                return BadRequest("Email Confrim not Successfull");
            }
            
        }

      
       
        
        [HttpPost("Security")]
        public async Task<IActionResult> ChangeSecurity([FromBody] LockOutDetailsInfoRequestDTO lockOutDetailsInfo)
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

                if (result != null)
                {
                    return Ok(
                        result);
                }
                else
                {
               

                    return BadRequest(
                      new AuthenticationResponseDTO
                      {
                          Message = "Token Request is failed"
                      });

                }
              
            }

            return BadRequest(new AuthenticationResponseDTO());
        }

        
        
        
        [HttpGet]
        [Route("Get-User-Details")]
        [Authorize]
        public async Task<IActionResult> GetUserDetails()
        {
            var currentUser = await _userManager.GetUserAsync(HttpContext.User);
            if (currentUser != null)
            {
                var mappedUser =_mapper.Map<UserModelResponseDTO>(currentUser);
                return Ok(mappedUser);
            }
            return BadRequest("Fetch user details is faild");
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
                    return BadRequest(new AuthenticationResponseDTO()
                    {
                        Message = "User is Not exist"
                    });
                    
                }
                if (user.TwoFactorAuthenticationCode != twoFAVerificatinRequestDTO.Code)
                {
                    return BadRequest(new AuthenticationResponseDTO()
                    {
                        Message = "Invalid Code or This code has been used"
                    });

    
                }
                if (user.TwoFactorAuthenticationCodeExpTime < DateTime.UtcNow)
                {
                    return BadRequest(new AuthenticationResponseDTO()
                    {
                        Message = "This code is Expired"
                    });
                  
                }
                var result = await _userManager.VerifyTwoFactorTokenAsync(user,"Email",twoFAVerificatinRequestDTO.Code);
                if (result == true)
                {
                    user.TwoFactorAuthenticationCode = null;
                    await _userManager.UpdateAsync(user);

                    return Ok( await GenenarateAuthenticatinResponse(user));
                }
            }
            return BadRequest(new AuthenticationResponseDTO()
            {
                Message = "fail"
            });
           
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
                    return Ok(
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
        public async Task<IActionResult> UpdateUser(UpdateUserRequest user) {
            Console.WriteLine("Model is not valid");
            if (ModelState.IsValid)
            {


                var exist_user= await _userManager.FindByIdAsync(user.Id);
                if (exist_user == null)
                {
                    return BadRequest("User is Not exist");
                }
                exist_user.EmailConfirmed = user.EmailConfirmed;
                exist_user.TwoFactorEnabled = user.TwoFactorEnabled;
                exist_user.LockoutEnd = user.LockoutEnd;
                exist_user.LockoutEnabled= user.LockoutEnabled;
                exist_user.AccessFailedCount = user.AccessFailedCount;
                exist_user.UpdateDate = DateTime.Now;
                var result =await _userManager.UpdateAsync(exist_user);
                if (result.Succeeded)
                {
                    Console.WriteLine("Update Success");
                    return Ok("Sucessfully Updated");
                }
                return BadRequest(result.Errors);
            }
            return BadRequest();

        
        }

        [HttpPost]
        [Route("Enable-2FA")]
        [Authorize]

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
                    user.UpdateDate = DateTime.Now;
                    await _userManager.UpdateAsync(user);
                  return  tFAEnableRequestDTO.IsEnable ?  Ok("2FA is Enabled")
                        :Ok("2FA is Disabled");
                }

            
            }
            return BadRequest();
        }


        
        [HttpPost]
        [Route("ChangePassword")]
        [Authorize]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequestDTO changePassword)
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


        //Reset Password Verification Email sender
        [HttpPost]
        [Route("ForgotPassword-Verification-Sender")]
        public async Task<IActionResult> ForgotPassword([FromBody] string email)
        {
            if (!ModelState.IsValid)
                return BadRequest("Invalid request");

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return BadRequest("Email does not exist");

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            Console.WriteLine(token);
            //NEED TO CHANGE
            var callback = $"https://localhost:7072/resetpassword?token={token}&email={Uri.EscapeDataString(user.Email)}";
            var emailBody = $"Dear User,\nYour Forgot Password verification link is: {callback}";

            var result = await _sendEmail.SendVerificationEmailAsync(email, emailBody);

            return result ? Ok("Check your email. We have sent a verification code to your email.")
                          : BadRequest("Failed to send email, try again.");
        }


        [HttpPost]
        [Route("ForgotPassword-ChangePassword")]
        public async Task<IActionResult> ResetPassword(ResetPasswordRequestDTO resetPasswordRequestDTO)
        {
            if (!ModelState.IsValid)
                return BadRequest("Invalid model");
            Console.WriteLine("token is "+resetPasswordRequestDTO.Token);
            var user = await _userManager.FindByEmailAsync(resetPasswordRequestDTO.Email);
            if (user == null)
                return BadRequest("Email does not exist");

            var decodeToken = Encoding.UTF8.GetString(Convert.FromBase64String(resetPasswordRequestDTO.Token));

            var resetPassResult = await _userManager.ResetPasswordAsync(user, decodeToken, resetPasswordRequestDTO.Password);
            if (!resetPassResult.Succeeded)
            {
                foreach (var error in resetPassResult.Errors)
                {
                    ModelState.TryAddModelError(error.Code, error.Description);
                }
                return BadRequest("Faild to reset Password");
            }

            return Ok("Password reset is successful");
        }




        // Generate Authentication response

        private async Task<AuthenticationResponseDTO> GenenarateAuthenticatinResponse(UserModel existing_user)
        {

            if (existing_user == null)
            {
               
                return new AuthenticationResponseDTO { Message = "User not found" };
            }
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


            await DetectInvalidLoginAttempts(true, existing_user);

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

        /*private async Task<bool> SendConfirmationEmailAsync(UserModel get_created_user)
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
            var callbackUrl = Url.Action("ConfirmEmail", "Account", new { userId = get_created_user.Id, code = encodedToken }, Request.Scheme ?? "https");

            var emailBody = ReturnConfirmationEmailbody(callbackUrl);

            return await _sendEmail.SendVerificationEmailAsync(get_created_user.Email!, emailBody);
        }*/

        private async Task<bool> SendConfirmationEmailAsync(UserModel get_created_user)
        {
            // Create Confirmation Email token for created user
            var emailConfirmedToken = await _userManager.GenerateEmailConfirmationTokenAsync(get_created_user);

            var encodedToken = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(emailConfirmedToken));

            // Store the encoded token in the database
            get_created_user.ConfirmationEmailLink = encodedToken;
            get_created_user.ConfirmationEmailLinkExpTime = DateTime.UtcNow.AddMinutes(2);
            await _userManager.UpdateAsync(get_created_user);

            // Create callback URL for the frontend
            var frontendUrl = "https://localhost:7072/confirm-Email-Successful"; // Update this to your frontend URL
            var callbackUrl = $"{frontendUrl}?userId={get_created_user.Id}&code={encodedToken}";

            var emailBody = ReturnConfirmationEmailbody(callbackUrl);

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
            var ip = HttpContext.Connection.RemoteIpAddress.ToString();
            UserDeviceInformation usrDeviceInformation = new UserDeviceInformation
            {
                UserAgentDetails = userAgent,
                Status = 1,
                IP = ip,
                UserId = new Guid(existing_user.Id),
                Email=existing_user!.Email!,


            };

            await _unitOfWorks.UserDeviceInformations.Add(usrDeviceInformation);
            await _unitOfWorks.CompleteAsync();
            return usrDeviceInformation;
        }

        private async Task DetectNewDeviceLogin(UserModel existing_user)
        {
            try
            {

                string? userAgent = Request.Headers["User-Agent"];
                

                //Check whether device info in database
                var deviceInfo = await _unitOfWorks.UserDeviceInformations.Checkinfo(new Guid(existing_user.Id), userAgent);

                if (deviceInfo == false)
                {
                    //save new info to data base

                    NotificationModel notification = new NotificationModel
                    {

                        Title = "Alert",
                        Content = "New Device Login Detected. Check your email to More details",
                        ReadStatus = false,
                        Type = NotificationType.Success,
                        AddedDate = DateTime.Now,
                        ReceiverId = new Guid(existing_user.Id),
                        Priority = 0,
                        Link = null
                    };

                    var nResult = await _httpClient.PostAsJsonAsync("https://localhost:7295/api/Notification/Create", notification);

                    var info = await StoreTheUserDataInformation(existing_user);
                    var details = UserAgentDetailsDTO.GetBrowser(info.UserAgentDetails!);
                    //send email new login detected

                    string htmlBody = $"Dear User,\r\n\r\nWe want to inform you that a new device was detected logging into your account." +
                        $"Your account security is our top priority, and we take such events seriously." +
                        $"\r\n\r\nDetails:\r\n\r\nDate and Time: {DateTime.Now}" +
                        $"\r\nDevice: {details.BrowserName} {details.DeviceType} \r\nLocation: [Insert Location, if available]" +
                        $"\r\nAction Required:\r\n\r\nIf this login was authorized by you, you may disregard this message.";

                    await _sendEmail.SendAlertEmailAsync(existing_user.UserName!, htmlBody);



                }
            }catch (Exception ex) { }

        }


        private async Task DetectInvalidLoginAttempts(bool isSuccess,UserModel user)
        {

            try {
                if (isSuccess)
                {

                    await _userManager.ResetAccessFailedCountAsync(user);

                }
                else { 
                    await _userManager.AccessFailedAsync(user);
                }

            }
            catch (Exception ex)
            {

                throw new Exception(ex.ToString());
            }

        }

        private string ReturnConfirmationEmailbody(string callbackUrl)
        {
            string ConfirmationMailBody = "<!DOCTYPE html>" +
                                 "<html>" +
                                     "<head>" +
                                         "<meta charset=\"utf-8\">" +
                                         "<meta http-equiv=\"x-ua-compatible\" content=\"ie=edge\">" +
                                         "<title>Email Confirmation</title>" +
                                         "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
                                         "<style type=\"text/css\">" +
                                             "@media screen {" +
                                                 "@font-face {" +
                                                     "font-family: 'Source Sans Pro';" +
                                                     "font-style: normal;" +
                                                     "font-weight: 400;" +
                                                     "src: local('Source Sans Pro Regular'), local('SourceSansPro-Regular'), url(https://fonts.gstatic.com/s/sourcesanspro/v10/ODelI1aHBYDBqgeIAH2zlBM0YzuT7MdOe03otPbuUS0.woff) format('woff');" +
                                                 "}" +
                                                 "@font-face {" +
                                                     "font-family: 'Source Sans Pro';" +
                                                     "font-style: normal;" +
                                                     "font-weight: 700;" +
                                                     "src: local('Source Sans Pro Bold'), local('SourceSansPro-Bold'), url(https://fonts.gstatic.com/s/sourcesanspro/v10/toadOcfmlt9b38dHJxOBGFkQc6VGVFSmCnC_l7QZG60.woff) format('woff');" +
                                                 "}" +
                                             "}" +
                                             "body, table, td, a {" +
                                                 "-ms-text-size-adjust: 100%;" +
                                                 "-webkit-text-size-adjust: 100%;" +
                                             "}" +
                                             "table, td {" +
                                                 "mso-table-rspace: 0pt;" +
                                                 "mso-table-lspace: 0pt;" +
                                             "}" +
                                             "a[x-apple-data-detectors] {" +
                                                 "font-family: inherit !important;" +
                                                 "font-size: inherit !important;" +
                                                 "font-weight: inherit !important;" +
                                                 "line-height: inherit !important;" +
                                                 "color: inherit !important;" +
                                                 "text-decoration: none !important;" +
                                             "}" +
                                             "div[style*=\"margin: 16px 0;\"] {" +
                                                 "margin: 0 !important;" +
                                             "}" +
                                             "body {" +
                                                 "width: 100% !important;" +
                                                 "height: 100% !important;" +
                                                 "padding: 0 !important;" +
                                                 "margin: 0 !important;" +
                                             "}" +
                                             "table {" +
                                                 "border-collapse: collapse !important;" +
                                             "}" +
                                             "a {" +
                                                 "color: #1a82e2;" +
                                             "}" +
                                             "body { background-color: #add8e6; text-align: center; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; padding: 20px; }" +
                                             "h1 { color: #1a82e2; }" +
                                             "h2 { color: #004d40; }" +
                                             "p { color: #004d40; font-size: 16px; }" +
                                             ".button { background-color: #1a82e2; color: white; padding: 15px 25px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px; border-radius: 5px; margin-top: 20px; }" +
                                             ".confirmation-label { color: #004d40; font-size: 50px; border: 3px solid #004d40; border-radius: 25px; padding: 10px; display: inline-block; margin-top: 20px; }" +
                                         "</style>" +
                                     "</head>" +
                                     "<body style=\"background-color: #e9ecef;\">" +
                                         "<div class=\"preheader\" style=\"display: none; max-width: 0; max-height: 0; overflow: hidden; font-size: 1px; line-height: 1px; color: #fff; opacity: 0;\">" +
                                             "A preheader is the short summary text that follows the subject line when an email is viewed in the inbox." +
                                         "</div>" +
                                         "<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\">" +
                                             "<tr>" +
                                                 "<td align=\"center\" bgcolor=\"#e9ecef\"></td>" +
                                             "</tr>" +
                                             "<tr>" +
                                                 "<td align=\"center\" bgcolor=\"#e9ecef\">" +
                                                     "<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"max-width: 600px;\">" +
                                                         "<tr>" +
                                                             "<td align=\"center\" bgcolor=\"#ffffff\" style=\"padding: 36px 24px 0; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; border-top: 3px solid #d4dadf;\">" +
                                                                 "<h1 style=\"margin: 0; font-size: 32px; font-weight: 700; letter-spacing: -1px; line-height: 48px;\">ERP System Faculty Of Engineering \nUniversity Of Ruhuna</h1>" +
                                                             "</td>" +
                                                         "</tr>" +
                                                     "</table>" +
                                                 "</td>" +
                                             "</tr>" +
                                             "<tr>" +
                                                 "<td align=\"center\" bgcolor=\"#e9ecef\">" +
                                                     "<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"max-width: 600px;\">" +
                                                         "<tr>" +
                                                             "<td align=\"left\" bgcolor=\"#ffffff\" style=\"padding: 24px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;\">" +
                                                                 "<p style=\"margin: 0;\">Tap the button below to confirm your email address. If you didn't create an account with <a href=\"https://sendgrid.com\">Paste</a>, you can safely delete this email.</p>" +
                                                             "</td>" +
                                                         "</tr>" +
                                                         "<tr>" +
                                                             "<td align=\"left\" bgcolor=\"#ffffff\">" +
                                                                 "<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\">" +
                                                                     "<tr>" +
                                                                         "<td align=\"center\" bgcolor=\"#ffffff\" style=\"padding: 12px;\">" +
                                                                             "<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\">" +
                                                                                 "<tr>" +
                                                                                     "<td align=\"center\" bgcolor=\"#1a82e2\" style=\"border-radius: 6px;\">" +
                                                                                         $"<a href=\"{callbackUrl}\" target=\"_blank\" style=\"display: inline-block; padding: 16px 36px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; color: #ffffff; text-decoration: none; border-radius: 6px;\">Click here to confirm your email address</a>" +
                                                                                     "</td>" +
                                                                                 "</tr>" +
                                                                             "</table>" +
                                                                         "</td>" +
                                                                     "</tr>" +
                                                                 "</table>" +
                                                             "</td>" +
                                                         "</tr>" +
                                                         "<tr>" +
                                                             "<td align=\"left\" bgcolor=\"#ffffff\" style=\"padding: 24px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px;\">" +
                                                                 "<p style=\"margin: 0;\">If that doesn't work, copy and paste the following link in your browser:</p>" +
                                                             "</td>" +
                                                         "</tr>" +
                                                         "<tr>" +
                                                             "<td align=\"left\" bgcolor=\"#ffffff\" style=\"padding: 24px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 16px; line-height: 24px; border-bottom: 3px solid #d4dadf\">" +
                                                                 $"<p style=\"margin: 0;\"><a href=\"{callbackUrl}\">{callbackUrl}</a></p>" +
                                                             "</td>" +
                                                         "</tr>" +
                                                     "</table>" +
                                                 "</td>" +
                                             "</tr>" +
                                             "<tr>" +
                                                 "<td align=\"center\" bgcolor=\"#e9ecef\" style=\"padding: 24px;\">" +
                                                     "<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"max-width: 600px;\">" +
                                                         "<tr>" +
                                                             "<td align=\"center\" bgcolor=\"#e9ecef\" style=\"padding: 12px 24px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 14px; line-height: 20px; color: #666;\">" +
                                                                 "<p style=\"margin: 0;\">You received this email because we received a request for email confirmation for your account. If you didn't request this, you can safely delete this email.</p>" +
                                                             "</td>" +
                                                         "</tr>" +
                                                         "<tr>" +
                                                             "<td align=\"center\" bgcolor=\"#e9ecef\" style=\"padding: 12px 24px; font-family: 'Source Sans Pro', Helvetica, Arial, sans-serif; font-size: 14px; line-height: 20px;color: #666;\">" +
                                                         "<p style=\"margin: 0;\">Paste 1234 S. Broadway St. City, State 12345</p>" +
                                                     "</td>" +
                                                 "</tr>" +
                                             "</table>" +
                                         "</td>" +
                                     "</tr>" +
                                 "</table>" +
                                 "<div class=\"confirmation-label\">✔</div>" +
                             "</body>" +
                         "</html>";

            return ConfirmationMailBody;
        }

        [HttpGet]
        [Route("test")]

        [Authorize]
        public async Task<IActionResult> Test()
        {
            return Ok ("Hello world, this is test authentication");
        }

    }

}
