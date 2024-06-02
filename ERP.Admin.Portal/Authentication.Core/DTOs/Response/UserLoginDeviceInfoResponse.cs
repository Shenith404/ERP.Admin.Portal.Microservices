using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.Core.DTOs.Response
{
    public class UserLoginDeviceInfoResponse
    {
        public Guid UserId { get; set; }

        public string Email { get; set; }

        public string? UserAgentDetails { get; set; }

        public DateTime LoginDate { get; set; } = DateTime.Now;

        public string? IP { get; set; }

        public int Status { get; set; }

       

    }
}
