using System;
using System.Threading.Tasks;
using Authentication.Api.Controllers;
using Authentication.Core.DTOs;
using Authentication.jwt;
using AutoFixture;
using EmailSender.SendEmail;
using ERP.Authentication.Core.DTOs;
using ERP.Authentication.Core.Entity;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Moq;
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

        //Not working
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
        public async Task Login_WithLockedUser_ShouldReturnUnAuthorized()
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
        public async Task Register_WithValidModel_ShouldReturnOk()
        {
            // Arrange
            var registerRequest = new AuthenticationRequestDTO
            {
                UserName = "newuser@example.com",
                Password = "Abc@1234",
            };

            var newUser = new UserModel
            {
                Email = registerRequest.UserName,
                UserName = registerRequest.UserName,
                Status = 1,
                EmailConfirmed = false,
            };

            _mockUserManager.Setup(x => x.FindByEmailAsync(registerRequest.UserName))
                            .ReturnsAsync((UserModel)null);

            _mockUserManager.Setup(x => x.FindByNameAsync(registerRequest.UserName))
                           .ReturnsAsync(newUser);

            _mockUserManager.Setup(x => x.CreateAsync(newUser, registerRequest.Password))
                            .ReturnsAsync(IdentityResult.Success);

            _mockUserManager.Setup(x => x.AddToRoleAsync(newUser, It.IsAny<string>()))
                            .ReturnsAsync(IdentityResult.Success);

            _mockUserManager.Setup(x => x.GenerateEmailConfirmationTokenAsync(It.IsAny<UserModel>()))
                            .ReturnsAsync("confirmation_token");

            _mockUserManager.Setup(x => x.UpdateAsync(It.IsAny<UserModel>()))
                            .ReturnsAsync(IdentityResult.Success);

            _mockSendEmail.Setup(x => x.SendVerificationEmailAsync(newUser.Email, It.IsAny<string>()))
                          .ReturnsAsync(true);

            // Act
            var result = await _controller.Register(registerRequest) as OkObjectResult;

            // Assert
            result.Should().NotBeNull();
            result.StatusCode.Should().Be(201);
            var response = result.Value as AuthenticationResponseDTO;
            response.Should().NotBeNull();
            response.Message.Should().Be("User registered successfully. Please check your email for verification.");

            // Verify user creation
            _mockUserManager.Verify(x => x.CreateAsync(newUser, registerRequest.Password), Times.Once);
            _mockUserManager.Verify(x => x.AddToRoleAsync(newUser, It.IsAny<string>()), Times.Once);
            _mockUserManager.Verify(x => x.GenerateEmailConfirmationTokenAsync(newUser), Times.Once);
            _mockUserManager.Verify(x => x.UpdateAsync(newUser), Times.Once);
            _mockSendEmail.Verify(x => x.SendVerificationEmailAsync(newUser.Email, It.IsAny<string>()), Times.Once);
        }

    }
}
