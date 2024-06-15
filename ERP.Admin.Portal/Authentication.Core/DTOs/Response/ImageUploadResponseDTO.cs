using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.Core.DTOs.Response
{
    public class ImageUploadResponseDTO
    {
        public string Messages { get; set; } =string.Empty;

        public bool UploadStatus { get; set; }


    }
}
