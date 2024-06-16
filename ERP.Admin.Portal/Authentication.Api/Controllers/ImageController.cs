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
using System.IO;
using System.Threading.Tasks;

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
        public async Task<IActionResult> Upload([FromForm] ImageUploadRequestDTO imageUploadRequest)
        {
            var user = await _userManager.FindByIdAsync(imageUploadRequest.UserId);
            if (user == null)
            {
                Console.WriteLine("Error occurred: User ID is not valid.");
                return BadRequest("User ID is not valid.");
            }

            var (status, message) = await ImageUploader(imageUploadRequest);
            if (status)
            {
                Console.WriteLine($"Image uploaded successfully: {message}");

                if (!string.IsNullOrEmpty(user.ImageName))
                {
                    var currentImagePath = Path.Combine(Directory.GetCurrentDirectory(), "Uploads", user.ImageName);
                    if (System.IO.File.Exists(currentImagePath))
                    {
                        try
                        {
                            System.IO.File.Delete(currentImagePath);
                            Console.WriteLine($"Deleted old image: {currentImagePath}");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error deleting old image: {ex.Message}");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"Old image not found: {currentImagePath}");
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
                    var uploadedImagePath = Path.Combine(Directory.GetCurrentDirectory(), "Uploads", message);
                    if (System.IO.File.Exists(uploadedImagePath))
                    {
                        try
                        {
                            System.IO.File.Delete(uploadedImagePath);
                            Console.WriteLine($"Deleted newly uploaded image due to update failure: {uploadedImagePath}");
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error deleting newly uploaded image: {ex.Message}");
                        }
                    }
                    Console.WriteLine("Failed to update user with new image.");
                    return BadRequest("Failed to update user with new image.");
                }
            }
            else
            {
                Console.WriteLine($"Error occurred: {message}");
                return BadRequest($"Error occurred: {message}");
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
                return (false, "File size exceeds limit. Only 1Mb allowed.");

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
