using Authentication.DataService.IConfiguration;
using Authentication.jwt;
using AutoMapper;
using ERP.Authentication.Core.Entity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Authentication.Api.Controllers
{

    //[Authorize(AuthenticationSchemes =JwtBearerDefaults.AuthenticationScheme)]
    [Route("api/[controller]")]
    [ApiController]
    public class ImageController : BaseController
    {

  

        private readonly string[] permittedExtensions = { ".jpg", ".jpeg", ".png", };
        private readonly long fileSizeLimit = 1024 * 1024;

        public ImageController(IJwtTokenHandler jwtTokenHandler, UserManager<UserModel> userManager, IMapper mapper, IUnitOfWorks unitOfWorks) 
            : base(jwtTokenHandler, userManager, mapper, unitOfWorks)
        {
        }

        [HttpPost]
        [Route("upload-image")]
        public async Task<IActionResult> Upload(IFormFile file)
        {
            if (file == null || file.Length == 0)
                return BadRequest("No file uploaded.");

            var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
            if (string.IsNullOrEmpty(ext) || Array.IndexOf(permittedExtensions, ext) < 0)
                return BadRequest("Invalid file type.");

            if (file.Length > fileSizeLimit)
                return BadRequest("File size exceeds limit.Only 1Mb Allowed");

            // Additional security checks can be added here, e.g., scanning the file for malicious content

            var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "Uploads");
            if (!Directory.Exists(uploadsFolder))
                Directory.CreateDirectory(uploadsFolder);

            var filePath = Path.Combine(uploadsFolder, Guid.NewGuid().ToString() + ext);
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            return Ok(new { FilePath = $"/Uploads/{Path.GetFileName(filePath)}" });
        }


        [HttpGet]
        [Route("image/{filename}")]
        public IActionResult GetImage(string filename)
        {
            var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "Uploads");
            var filePath = Path.Combine(uploadsFolder, filename);

            if (!System.IO.File.Exists(filePath))
            {
                return NotFound("Image not found.");
            }

            var ext = Path.GetExtension(filename).ToLowerInvariant();
            if (string.IsNullOrEmpty(ext) || Array.IndexOf(permittedExtensions, ext) < 0)
            {
                return BadRequest("Invalid file type.");
            }

            var fileBytes = System.IO.File.ReadAllBytes(filePath);
            return File(fileBytes, $"image/{ext.TrimStart('.')}");
        }

    }
}
