

using System.ComponentModel.DataAnnotations;

namespace Authentication.Core.DTOs.Request
{
    public class AuthenticationRequestDTO
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }


    }
}
