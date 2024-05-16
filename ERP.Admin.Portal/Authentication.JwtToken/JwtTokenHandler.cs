using Authentication.Core.DTOs.Common;
using Authentication.Core.DTOs.Request;
using Authentication.Core.DTOs.Response;
using Authentication.Core.Entity;
using Authentication.DataService.IConfiguration;
using ERP.Authentication.Core.Entity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;


namespace Authentication.jwt
{
    public class JwtTokenHandler : IJwtTokenHandler
    {
        string key = Environment.GetEnvironmentVariable("JWT_SECRET_KEY")!;

        private const int JWT_VALIDITY_MINS = 10;
        private readonly IUnitOfWorks _unitOfWorks;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly UserManager<UserModel> _userManager;

        public JwtTokenHandler(IUnitOfWorks unitOfWorks,
            TokenValidationParameters tokenValidationParameters,
            UserManager<UserModel> userManager)
        {
            _userManager = userManager;
            _unitOfWorks = unitOfWorks;
            _tokenValidationParameters = tokenValidationParameters;
        }

        public  async Task<AuthenticationResponseDTO ?>  GenerateJwtToken(TokenRequestDTO request)
        {
            if (string.IsNullOrWhiteSpace(request.UserName) )
            {
                return null;
            }

            /*var userAccount = _userAccounts.Where(x => x.UserName.Equals(request.UserName) && x.Password.Equals(request.Password))
                .FirstOrDefault();

            if (userAccount == null)
                return null;*/

            var tokenExpiryTimeStamp = DateTime.Now.AddMinutes(JWT_VALIDITY_MINS);
            var tokenKey = Encoding.ASCII.GetBytes(key);
      

            var claimsIdentity = new ClaimsIdentity(
                new List<Claim>
                {
                  new Claim("Id", request.UserId),
                  new Claim(JwtRegisteredClaimNames.Name, request.UserName),
                  new Claim(ClaimTypes.NameIdentifier, request.UserId),
                  new Claim(ClaimTypes.Role, request.Role),
                  new Claim(JwtRegisteredClaimNames.Sub ,request.UserName),
                  new Claim(JwtRegisteredClaimNames.Jti ,Guid.NewGuid().ToString()),
                  new Claim(JwtRegisteredClaimNames.Iat,DateTime.Now.ToUniversalTime().ToString()),
                });


            var signinCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(tokenKey),
                    SecurityAlgorithms.HmacSha256Signature
                );

            var securityTokenDescripter = new SecurityTokenDescriptor
            {
                Subject = claimsIdentity,
                Expires = tokenExpiryTimeStamp,
                SigningCredentials = signinCredentials
            };

            //create jwt token
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescripter);
            var token = jwtSecurityTokenHandler.WriteToken(securityToken);


            //create refresh token
            var refreshtoken = new RefreshToken
            {
                Token = $"{RandomStringGenerator(25)}_{Guid.NewGuid()}" ,
                UserId = request.UserId,
                IsRevoked = false,
                IsUsed = false,
                Status=1,
                JwtId= securityToken.Id,
                ExpiredDate= DateTime.UtcNow.AddMonths(1),
            };
            await _unitOfWorks.RefreshToknes.Add(refreshtoken);
            await _unitOfWorks.CompleteAsync();


            return new AuthenticationResponseDTO
            {
                UserName = request.UserName,
                ExpiresIn = (int)tokenExpiryTimeStamp.Subtract(DateTime.Now).TotalSeconds,
                JwtToken = token,
                RefreshToken =refreshtoken.Token,
            };

        }

       public async Task<AuthenticationResponseDTO?> VerifyToken(TokenInfoDTO tokenInfoDTO)
        {
            var tokenhandler = new JwtSecurityTokenHandler();
            try
            {
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(key)),
                    ValidateLifetime = false, // Ignore token expiration
                };

                var principle = tokenhandler.ValidateToken(tokenInfoDTO.JwtToken, tokenValidationParameters, out var ValidateToken);

                if (ValidateToken is JwtSecurityToken jwtSecurityToken)
                {
                    var isAlgorithmValid = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);
                    if (!isAlgorithmValid)
                    {
                        Console.WriteLine("Invalid token algorithm");
                        return null;
                    }
                }

        var expClaim = principle.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp);
        if (expClaim == null || !long.TryParse(expClaim.Value, out long utcExpireDate))
        {
            Console.WriteLine("Invalid or missing expiration claim");
            return null;
        }

        var expDate = UnixTimeStampToDateTime(utcExpireDate);

        if (expDate > DateTime.UtcNow)
        {
            Console.WriteLine("JWT token is not expired");
            return null; // JWT token is not expired
        }

        // JWT token is expired, check refresh token
        var refreshTokenExist = await _unitOfWorks.RefreshToknes.GetByRefreshToken(tokenInfoDTO.RefreshToken);
        if (refreshTokenExist == null)
        {
            Console.WriteLine("Invalid refresh token");
            return null; // Invalid refresh token
        }

        if (refreshTokenExist.ExpiredDate < DateTime.UtcNow || refreshTokenExist.IsUsed)
        {
            Console.WriteLine("Refresh token is expired or already used");
            return null; // Refresh token is expired or already used
        }

        if (refreshTokenExist.IsRevoked)
        {
            Console.WriteLine("Refresh token is revoked");
            return null; // Refresh token is revoked
        }

        // Mark refresh token as used
        refreshTokenExist.IsUsed = true;
        await _unitOfWorks.RefreshToknes.MarkRefreshTokenAsUser(refreshTokenExist);
        await _unitOfWorks.CompleteAsync();

        // Generate new JWT token
        var dbUser = await _userManager.FindByIdAsync(refreshTokenExist.UserId);
        if (dbUser == null)
        {
            Console.WriteLine("Invalid user");
            return null; // Invalid user
        }

        var tokenRequest = new TokenRequestDTO
        {
            UserName = dbUser.UserName!,
            Role = (await _userManager.GetRolesAsync(dbUser))[0],
            UserId = dbUser.Id
        };

        var newToken = await GenerateJwtToken(tokenRequest);
        if (newToken != null)
        {
            newToken.EmailConfirmed = dbUser.EmailConfirmed;
            newToken.IsLocked = await _userManager.IsLockedOutAsync(dbUser);
                    Console.WriteLine("Refresh token requested");
            return newToken; // New JWT token generated successfully
        }

        Console.WriteLine("Failed to generate new JWT token");
        return null; // Failed to generate new JWT token
    }
      catch (SecurityTokenExpiredException)
     {
                
        Console.WriteLine("JWT token is expired");
            
         return null;
    }

    catch (Exception ex)
    {
        Console.WriteLine($"Error occurred: {ex.Message}");
        return null; // Error occurred
    }
}

        private DateTime UnixTimeStampToDateTime(long unixDate)
        {
            //set the time to 1 jan 1970
            var dateTime = new DateTime(1970 ,1,1 ,0,0,0,0,DateTimeKind.Utc);
            //Add the number of second from 1 jan 1970
            dateTime = dateTime.AddSeconds(unixDate).ToUniversalTime();
            return dateTime;
        }

        private string  RandomStringGenerator(int length)
        {
            var random =new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }

      
    }
}
