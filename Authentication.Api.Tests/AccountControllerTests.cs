using System;
using System.Threading.Tasks;
using Authentication.Api.Controllers;
using Authentication.Core.DTOs.Common;
using Authentication.Core.DTOs.Request;
using Authentication.Core.DTOs.Response;
using Authentication.jwt;
using AutoFixture;
using EmailSender.SendEmail;
using ERP.Authentication.Core.Entity;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Moq;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Authentication.Api.Tests
{
    public class AccountControllerTests
    {
        private readonly Mock<UserManager<UserModel>> _mockUserManager;
        private readonly Mock<IJwtTokenHandler> _mockJwtTokenHandler;
        private readonly Mock<ISendEmail> _mockSendEmail;
        private readonly AccountController _controller;
        private readonly IFixture _fixture;

        public AccountControllerTests()
        {

            
            _mockUserManager = new Mock<UserManager<UserModel>>(
                new Mock<IUserStore<UserModel>>().Object,
                null, null, null, null, null, null, null, null);
            _mockJwtTokenHandler = new Mock<IJwtTokenHandler>();
            _mockSendEmail = new Mock<ISendEmail>();
            _fixture = new Fixture();
          

            _controller = new AccountController(_mockJwtTokenHandler.Object, _mockUserManager.Object, null, _mockSendEmail.Object, null);
        }


        /// <summary>
        /// LOGIN USER
        /// </summary>
        /// <returns></returns>

        [Fact]
        public async Task Login_With_InValidCredentials_ShouldReturnUnothorized()
        {
            // Arrange
            var authenticationRequest = new AuthenticationRequestDTO
            {
                UserName = "string@gmail.com",
                Password = "Abc@1234"
            };

            var existingUser = new UserModel
            {
                Email = "test@example.com",
                Status = 1,
                EmailConfirmed = true
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(authenticationRequest.UserName))
                .ReturnsAsync(existingUser);

            _mockUserManager.Setup(x => x.IsLockedOutAsync(existingUser))
                .ReturnsAsync(false);

            _mockUserManager.Setup(x => x.IsEmailConfirmedAsync(existingUser))
                .ReturnsAsync(true);

            _mockUserManager.Setup(x => x.CheckPasswordAsync(existingUser, authenticationRequest.Password))
                .ReturnsAsync(false);

            



            // Act
            var result = await _controller.Login(authenticationRequest) as UnauthorizedObjectResult;

            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(401);
            var response = result.Value as AuthenticationResponseDTO;
            response.Should().NotBeNull();
            response.UserName.Should().Be(null);
            response.Message.Should().Be("Password is Incorrect");
            response.EmailConfirmed.Should().Be(null);
            response.JwtToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
            response.ExpiresIn.Should().Be(0);
            response.Is2FAConfirmed.Should().BeNull();
        }

        [Fact]
        public async Task Login_With_Deleted_Email_ShouldReturnUnothorized()
        {
            // Arrange
            var authenticationRequest = new AuthenticationRequestDTO
            {
                UserName = "string@gmail.com",
                Password = "Abc@1234"
            };

            var existingUser = new UserModel
            {
                Email = "test@example.com",
                Status = 0,
                EmailConfirmed = true
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(authenticationRequest.UserName))
                .ReturnsAsync(existingUser);

            _mockUserManager.Setup(x => x.IsLockedOutAsync(existingUser))
                .ReturnsAsync(false);

            _mockUserManager.Setup(x => x.IsEmailConfirmedAsync(existingUser))
                .ReturnsAsync(true);

            _mockUserManager.Setup(x => x.CheckPasswordAsync(existingUser, authenticationRequest.Password))
                .ReturnsAsync(false);

            



            // Act
            var result = await _controller.Login(authenticationRequest) as UnauthorizedObjectResult;

            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(401);
            var response = result.Value as AuthenticationResponseDTO;
            response.Should().NotBeNull();
            response.UserName.Should().Be(null);
            response.Message.Should().Be("This user is Deleted");
            response.EmailConfirmed.Should().Be(null);
            response.JwtToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
            response.ExpiresIn.Should().Be(0);
            response.Is2FAConfirmed.Should().BeNull();
        }

        [Fact]
        public async Task Login_WithValidCredentials_ShouldReturnOk()
        {
            // Arrange
            var authenticationRequest = new AuthenticationRequestDTO
            {
                UserName = "string@gmail.com",
                Password = "Abc@1234"
            };

            var existingUser = new UserModel
            {
                Email = "test@example.com",
                Status = 1,
                EmailConfirmed = true
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(authenticationRequest.UserName))
                .ReturnsAsync(existingUser);

            _mockUserManager.Setup(x => x.IsLockedOutAsync(existingUser))
                .ReturnsAsync(false);

            _mockUserManager.Setup(x => x.IsEmailConfirmedAsync(existingUser))
                .ReturnsAsync(true);

            _mockUserManager.Setup(x => x.CheckPasswordAsync(existingUser, authenticationRequest.Password))
                .ReturnsAsync(true);

            _mockJwtTokenHandler.Setup(x => x.GenerateJwtToken(It.IsAny<TokenRequestDTO>()))
                .ReturnsAsync(new AuthenticationResponseDTO { JwtToken = "dummyToken" });

            _mockUserManager.Setup(x => x.GetRolesAsync(existingUser))
                .ReturnsAsync(["Reguler"]);



            // Act
            var result = await _controller.Login(authenticationRequest) as OkObjectResult;

            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(200);
            var response = result.Value as AuthenticationResponseDTO;
            response.Should().NotBeNull();
            response.UserName.Should().Be(existingUser.UserName);
            response.Message.Should().Be("User Login Successfully");
            response.JwtToken.Should().Be("dummyToken");
            response.EmailConfirmed.Should().Be(true);
        }

        [Fact]
        public async Task Login_WithTwoFactorAuthenticationEnabled_ShouldReturnUnauthorized()
        {
            // Arrange
            var authenticationRequest = new AuthenticationRequestDTO
            {
                UserName = "yamudacarpool@gmail.com",
                Password = "Abc@1234"
            };

            var existingUser = new UserModel
            {
                Email = "yamudacarpool@gmail.com",
                Status = 1,
                EmailConfirmed = true,
                TwoFactorEnabled = true
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(authenticationRequest.UserName))
                            .ReturnsAsync(existingUser);

            _mockUserManager.Setup(x => x.CheckPasswordAsync(existingUser, authenticationRequest.Password))
                            .ReturnsAsync(true);

            _mockUserManager.Setup(x => x.GenerateTwoFactorTokenAsync(existingUser, "Email"))
                            .ReturnsAsync("123456");

            _mockSendEmail.Setup(x => x.SendVerificationEmailAsync(existingUser.Email, It.IsAny<string>()))
                          .ReturnsAsync(true);

            _mockUserManager.Setup(x => x.IsLockedOutAsync(existingUser))
                            .ReturnsAsync(false);

            _mockUserManager.Setup(x => x.IsEmailConfirmedAsync(existingUser))
                            .ReturnsAsync(true);
            _mockUserManager.Setup(x => x.UpdateAsync(existingUser))
                .ReturnsAsync(IdentityResult.Success);

            // Act
            var result = await _controller.Login(authenticationRequest) as UnauthorizedObjectResult;

            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(401);
            var response = result.Value as AuthenticationResponseDTO;
            response.Should().NotBeNull();
            response.Is2FAConfirmed.Should().BeTrue();
            response.UserName.Should().Be(null);
            response.EmailConfirmed.Should().Be(null);
            response.JwtToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
            response.ExpiresIn.Should().Be(0);
            response.Message.Should().Contain($"We have sent verification code to your  email *******{existingUser.Email!.Substring(4)}");
        }

        [Fact]
        public async Task Login_WithLockedUser_Should_ReturnUnAuthorized()
        {
            // Arrange
            var authenticationRequest = new AuthenticationRequestDTO
            {
                UserName = "test@example.com",
                Password = "Abc@1234"
            };

            var lockedUser = new UserModel
            {
                Email = "test@example.com",
                Status = 1,
                EmailConfirmed = true,
                LockoutEnd = DateTimeOffset.MaxValue
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(authenticationRequest.UserName))
                .ReturnsAsync(lockedUser);
            _mockUserManager.Setup(x => x.IsLockedOutAsync(lockedUser))
                .ReturnsAsync(true);

            // Act
            var result = await _controller.Login(authenticationRequest) as UnauthorizedObjectResult;

            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(401);
            var response = result.Value as AuthenticationResponseDTO;
            response.Should().NotBeNull();
            response.IsLocked.Should().BeTrue();
            response.UserName.Should().Be(null);
            response.EmailConfirmed.Should().Be(null);
            response.JwtToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
            response.ExpiresIn.Should().Be(0);
            response.Message.Should().Be("This user is Locked");
            response.Is2FAConfirmed.Should().BeNull();
        }

        [Fact]
        public async Task Login_WithUnconfirmedEmail_ShouldReturnUnothorized()
        {
            // Arrange
            var authenticationRequest = new AuthenticationRequestDTO
            {
                UserName = "test@example.com",
                Password = "Abc@1234"
            };

            var unconfirmedUser = new UserModel
            {
                Email = "test@example.com",
                Status = 1,
                EmailConfirmed = false
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(authenticationRequest.UserName))
                .ReturnsAsync(unconfirmedUser);

            _mockUserManager.Setup(x => x.IsLockedOutAsync(unconfirmedUser))
                .ReturnsAsync(false);

            // Act
            var result = await _controller.Login(authenticationRequest) as UnauthorizedObjectResult;

            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(401);
            var response = result.Value as AuthenticationResponseDTO;
            response.Should().NotBeNull();
            response.EmailConfirmed.Should().BeFalse();
            response.UserName.Should().Be(null);
            response.JwtToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
            response.ExpiresIn.Should().Be(0);
            response.Is2FAConfirmed.Should().BeNull();
            response.Message.Should().Be("Your Email is not Confirmed");
        }



        /// <summary>
        /// CREATE USER
        /// </summary>
        /// <returns></returns>
        
        [Fact]
        public async Task Register_With_Exist_Email_ShouldReturnBadRequest()
        {
            // Arrange
            var registerRequest = new AuthenticationRequestDTO
            {
                UserName = "newuser@example.com",
                Password = "Abc@1234",
            };

            
            var get_created_user = new UserModel
            {
                Email = registerRequest.UserName,
                UserName = registerRequest.UserName,
                Status = 1,
                EmailConfirmed = false,
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(registerRequest.UserName))
                            .ReturnsAsync(get_created_user);

           

            // Act
            var result = await _controller.Register(registerRequest) as BadRequestObjectResult;

            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(400);
            var response = result.Value as AuthenticationResponseDTO;
            response.Should().NotBeNull();
            response.IsLocked.Should().BeNull();
            response.UserName.Should().Be(null);
            response.EmailConfirmed.Should().Be(null);
            response.JwtToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
            response.ExpiresIn.Should().Be(0);
            response.Is2FAConfirmed.Should().BeNull();
            response.Message.Should().Be("Email is Already Exist");

           }
        [Fact]
        public async Task Register_With_Deleted_Email_ShouldReturnBadRequest()
        {
            // Arrange
            var registerRequest = new AuthenticationRequestDTO
            {
                UserName = "newuser@example.com",
                Password = "Abc@1234",
            };

            
            var get_created_user = new UserModel
            {
                Email = registerRequest.UserName,
                UserName = registerRequest.UserName,
                Status = 0,
                EmailConfirmed = false,
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(registerRequest.UserName))
                            .ReturnsAsync(get_created_user);

           

            // Act
            var result = await _controller.Register(registerRequest) as BadRequestObjectResult;

            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(400);
            var response = result.Value as AuthenticationResponseDTO;
            response.Should().NotBeNull();
            response.IsLocked.Should().BeNull();
            response.UserName.Should().Be(null);
            response.EmailConfirmed.Should().Be(null);
            response.JwtToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
            response.ExpiresIn.Should().Be(0);
            response.Is2FAConfirmed.Should().BeNull();
            response.Message.Should().Be("You cant user this email");

           }


        [Fact]
        public async Task If_User_creation_fail_Output_ShouldBe_BadRequest()
        {
            // Arrange
            var registerRequest = new AuthenticationRequestDTO
            {
                UserName = "newuser@example.com",
                Password = "Abc@1234",
            };

            var newUser = new UserModel
            {
                Email = "newuser@gmail.com",
                UserName = "newuser@gmail.com",
                Status = 1,
            };
            var get_created_user = new UserModel
            {
                Email = registerRequest.UserName,
                UserName = registerRequest.UserName,
                Status = 1,
                EmailConfirmed = false,
                Id = "e03d579d-70d4-4e7b-bf79-9e2e8f3fb6f7",
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(registerRequest.UserName))
                            .ReturnsAsync((UserModel)null);

            _mockUserManager.Setup(x => x.FindByNameAsync(registerRequest.UserName))
                           .ReturnsAsync((UserModel)null);


            _mockUserManager.Setup(x => x.CreateAsync(It.IsAny<UserModel>(), registerRequest.Password))
                .ReturnsAsync(IdentityResult.Failed());

            _mockUserManager.Setup(x => x.AddToRoleAsync(get_created_user, It.IsAny<string>()))
                            .ReturnsAsync(IdentityResult.Success);

            _mockUserManager.Setup(x => x.GenerateEmailConfirmationTokenAsync(It.IsAny<UserModel>()))
                            .ReturnsAsync("confirmation_token");

            _mockUserManager.Setup(x => x.UpdateAsync(It.IsAny<UserModel>()))
                            .ReturnsAsync(IdentityResult.Success);

            _mockSendEmail.Setup(x => x.SendVerificationEmailAsync(get_created_user.Email, It.IsAny<string>()))
                          .ReturnsAsync(true);



            // Act
            var result = await _controller.Register(registerRequest) as BadRequestObjectResult;

            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(400);
            var response = result.Value as AuthenticationResponseDTO;
            response.Should().NotBeNull();
            response.IsLocked.Should().BeNull();
            response.UserName.Should().Be(null);
            response.EmailConfirmed.Should().Be(null);
            response.JwtToken.Should().BeNull();
            response.RefreshToken.Should().BeNull();
            response.ExpiresIn.Should().Be(0);
            response.Is2FAConfirmed.Should().BeNull();
            response.Message.Should().Be("Server Error");

        }




        //CONFRIM EMAIL

        [Fact]
        public async Task With_Null_UserId_and_Valid_Code_Output_ShouldBe_BadRequest()
        {
            //Arange

            string  UserId = null;
            string code = It.IsAny<string>();


            //Act

            var result = await _controller.ConfirmEmail(UserId!, code) as BadRequestObjectResult;


            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(400);
            var response = result.Value as string;
            response.Should().NotBeNull();
            response.Should().Be("Invalid Email Confirm Url");

        }
    
        [Fact]
        public async Task With_InValid_UserId_and_Valid_Code_Output_ShouldBe_BadRequest()
        {
            //Arange

            string  UserId = "e03d579d-70d4-4e7b-bf79-9e2e8f3fb6f7";
            string code = "sdfsdkfl;skaf;lksf";

            _mockUserManager.Setup(x => x.FindByIdAsync(It.IsAny<string>()))
                .ReturnsAsync((UserModel)null);


            //Act

            var result = await _controller.ConfirmEmail(UserId, code) as BadRequestObjectResult;


            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(400);
            var response = result.Value as string;
            response.Should().NotBeNull();
            response.Should().Be("Invalid Email");

        }
    
        [Fact]
        public async Task With_Used_Confirmation_Email_Code_Output_ShouldBe_BadRequest()
        {
            //Arange

            string  UserId = "e03d579d-70d4-4e7b-bf79-9e2e8f3fb6f7";
            string code = "sdfsdkfl;skaf;lksf";

            var User = new UserModel()
            {

                UserName = "Test@test.com",
                ConfirmationEmailLink= "sdf"
            };

            _mockUserManager.Setup(x => x.FindByIdAsync(It.IsAny<string>()))
                .ReturnsAsync(User);


            //Act

            var result = await _controller.ConfirmEmail(UserId, code) as BadRequestObjectResult;


            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(400);
            var response = result.Value as string;
            response.Should().NotBeNull();
            response.Should().Be("This link has been used");

        }
    
    
        [Fact]
        public async Task With_Exp_Confirmation_Email_Code_Output_ShouldBe_BadRequest()
        {
            //Arange

            string  UserId = "e03d579d-70d4-4e7b-bf79-9e2e8f3fb6f7";
            string code = "VGhpcyBpcyBhIGJhc2UtNjQgc3RyaW5nLg==";

            var User = new UserModel()
            {

                UserName = "Test@test.com",
                ConfirmationEmailLink = "VGhpcyBpcyBhIGJhc2UtNjQgc3RyaW5nLg==",
                ConfirmationEmailLinkExpTime = DateTime.UtcNow
            };

            _mockUserManager.Setup(x => x.FindByIdAsync(It.IsAny<string>()))
                .ReturnsAsync(User);


            //Act

            var result = await _controller.ConfirmEmail(UserId, code) as BadRequestObjectResult;


            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(400);
            var response = result.Value as string;
            response.Should().NotBeNull();
            response.Should().Be("This link is expired");

        }
    
        [Fact]
        public async Task With_Invalid_Confirmation_Email_Code_Output_ShouldBe_BadRequest()
        {
            //Arange

            string  UserId = "e03d579d-70d4-4e7b-bf79-9e2e8f3fb6f7";
            string code = "VGhpcyBpcyBhIGJhc2UtNjQgc3RyaW5nLg==";

            var User = new UserModel()
            {

                UserName = "Test@test.com",
                ConfirmationEmailLink = "VGhpcyBpcyBhIGJhc2UtNjQgc3RyaW5nLg==",
                ConfirmationEmailLinkExpTime = DateTime.UtcNow.AddDays(1)
            };

            _mockUserManager.Setup(x => x.FindByIdAsync(It.IsAny<string>()))
                .ReturnsAsync(User);

             _mockUserManager.Setup(x => x.ConfirmEmailAsync(It.IsAny<UserModel>(),It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Failed());


            //Act

            var result = await _controller.ConfirmEmail(UserId, code) as BadRequestObjectResult;


            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(400);
            var response = result.Value as string;
            response.Should().NotBeNull();
            response.Should().Be("Email Confrim not Successfull");

        }
    
        [Fact]
        public async Task With_valid_Confirmation_Email_Code_Output_ShouldBe_Ok()
        {
            //Arange

            string  UserId = "e03d579d-70d4-4e7b-bf79-9e2e8f3fb6f7";
            string code = "VGhpcyBpcyBhIGJhc2UtNjQgc3RyaW5nLg==";

            var User = new UserModel()
            {

                UserName = "Test@test.com",
                ConfirmationEmailLink = "VGhpcyBpcyBhIGJhc2UtNjQgc3RyaW5nLg==",
                ConfirmationEmailLinkExpTime = DateTime.UtcNow.AddDays(1)
            };

            _mockUserManager.Setup(x => x.FindByIdAsync(It.IsAny<string>()))
                .ReturnsAsync(User);

             _mockUserManager.Setup(x => x.ConfirmEmailAsync(It.IsAny<UserModel>(),It.IsAny<string>()))
                .ReturnsAsync(IdentityResult.Success);

              _mockUserManager.Setup(x => x.UpdateAsync(It.IsAny<UserModel>()))
                .ReturnsAsync(IdentityResult.Success);


            //Act

            var result = await _controller.ConfirmEmail(UserId, code) as OkObjectResult;


            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(200);
            var response = result.Value as string;
            response.Should().NotBeNull();
            response.Should().Be("Email Confrim is Successfull");

        }
    
    
    

       //REQUEST REFRESH TOKEN

        [Fact]
        public async Task With_Invalid_User_Tokens_OutPut_ShouldBe_UnAuthorized()
        {
            //Arange 

            TokenInfoDTO tokenInfoDTO = new TokenInfoDTO { 
            JwtToken= "askdfjsklajflsdf",
            RefreshToken="sfjklsajfklsjf"
            };

            _mockJwtTokenHandler.Setup(x => x.VerifyToken(tokenInfoDTO))
                .ReturnsAsync((AuthenticationResponseDTO)null);

            //Act

            var result = await _controller.RefreshToken(tokenInfoDTO) as UnauthorizedObjectResult;


            //Assert
            result.Should().NotBeNull();
            var response = result.Value as AuthenticationResponseDTO;
            response.Should().NotBeNull();
            response.Message.Should().Be("Token Request is failed");
            
        }


        [Fact]
        public async Task With_valid_User_Tokens_OutPut_ShouldBe_Ok()
        {
            //Arange 

            TokenInfoDTO tokenInfoDTO = new TokenInfoDTO
            {
                JwtToken = "askdfjsklajflsdf",
                RefreshToken = "sfjklsajfklsjf"
            };

            AuthenticationResponseDTO authenticationResponse =
                new AuthenticationResponseDTO { 

                    JwtToken="dasfasfdsadfsfsdafsdf",
                    RefreshToken="sfasfasfasfkklsf",
                    ExpiresIn=599
                
                
                };

            _mockJwtTokenHandler.Setup(x => x.VerifyToken(tokenInfoDTO))
                .ReturnsAsync(authenticationResponse);

            //Act

            var result = await _controller.RefreshToken(tokenInfoDTO) as OkObjectResult;


            //Assert
            result.Should().NotBeNull();
            var response = result.Value as AuthenticationResponseDTO;
            response.Should().NotBeNull();
            response.JwtToken.Should().NotBeNull();
            response.RefreshToken.Should().NotBeNull();
            response.ExpiresIn.Should().NotBe(0);

        }
    }
}
