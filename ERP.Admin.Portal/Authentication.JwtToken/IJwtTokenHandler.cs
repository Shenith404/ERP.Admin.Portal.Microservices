using Authentication.Core.DTOs.Common;
using Authentication.Core.DTOs.Request;
using Authentication.Core.DTOs.Response;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.jwt
{
    public interface IJwtTokenHandler
    {
        public  Task<AuthenticationResponseDTO?> GenerateJwtToken(TokenRequestDTO request);

        public Task<AuthenticationResponseDTO?> VerifyToken(TokenInfoDTO tokenInfoDTO);
    }
}
