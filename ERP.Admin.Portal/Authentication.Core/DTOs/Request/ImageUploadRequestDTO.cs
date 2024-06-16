using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.Core.DTOs.Request
{
    public class ImageUploadRequestDTO
    {

        public IFormFile File { get; set; }

        public string UserId { get; set; }
    }
}
