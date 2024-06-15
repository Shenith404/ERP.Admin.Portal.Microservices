using Authentication.Core.DTOs.Request;
using Authentication.DataService.IConfiguration;
using Authentication.jwt;
using AutoMapper;
using ERP.Authentication.Core.Entity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace Authentication.Api.Controllers
{
    //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
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
        public async Task<IActionResult> Upload(ImageUploadRequestDTO imageUploadRequest)
        {
            var user = await _userManager.FindByIdAsync(imageUploadRequest.UserId);
            if (user == null)
            {
                return BadRequest("User Id is not valid");
            }

            var (status, message) = await ImageUploader(imageUploadRequest);

            if (status)
            {
                // Need to delete current saved image
                if (!string.IsNullOrEmpty(user.ImageName))
                {
                    var currentImagePath = Path.Combine(Directory.GetCurrentDirectory(), user.ImageName.TrimStart('/'));
                    if (System.IO.File.Exists(currentImagePath))
                    {
                        System.IO.File.Delete(currentImagePath);
                    }
                }

                user.ImageName = message;
                var updateResult = await _userManager.UpdateAsync(user);
                if (updateResult.Succeeded)
                {
                    return Ok(message);
                }
                else
                {
                    // Need to delete uploaded image
                    var uploadedImagePath = Path.Combine(Directory.GetCurrentDirectory(), message.TrimStart('/'));
                    if (System.IO.File.Exists(uploadedImagePath))
                    {
                        System.IO.File.Delete(uploadedImagePath);
                    }
                    return BadRequest("Failed to update user with new image.");
                }
            }
            else
            {
                return BadRequest(message);
            }
        }

        [HttpPost]
        [Route("image")]
        public IActionResult GetImage([FromBody] string filename)
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

        private async Task<(bool, string)> ImageUploader(ImageUploadRequestDTO imageUploadRequest)
        {
            var file = imageUploadRequest.File;
            if (file == null || file.Length == 0)
                return (false, "No file uploaded.");

            var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
            if (string.IsNullOrEmpty(ext) || Array.IndexOf(permittedExtensions, ext) < 0)
                return (false, "Invalid file type.");

            if (file.Length > fileSizeLimit)
                return (false, "File size exceeds limit. Only 1Mb Allowed");

            // Additional security checks can be added here, e.g., scanning the file for malicious content

            var uploadsFolder = Path.Combine(Directory.GetCurrentDirectory(), "Uploads");
            if (!Directory.Exists(uploadsFolder))
                Directory.CreateDirectory(uploadsFolder);

            var filePath = Path.Combine(uploadsFolder, Guid.NewGuid().ToString() + ext);
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            return (true, $"{Path.GetFileName(filePath)}");
        }
    }
}
