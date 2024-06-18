using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using System.Diagnostics;

namespace Authentication.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DatabaseController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly string[] permittedExtensions = { ".bak", ".sql" };

        public DatabaseController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost]
        [Route("backup-sqlserver")]
        public async Task<IActionResult> BackupSqlServer()
        {
            try
            {
                var backupFolder = Path.Combine(Directory.GetCurrentDirectory(), "Backups");
                if (!Directory.Exists(backupFolder))
                    Directory.CreateDirectory(backupFolder);

                var backupFilePath = Path.Combine(backupFolder, $"mydb_backup_{DateTime.Now:yyyyMMddHHmmss}.bak");
                var connectionString = _configuration.GetConnectionString("DefaultConnection");

                using (var connection = new SqlConnection(connectionString))
                {
                    var query = $"BACKUP DATABASE [mydb] TO DISK = '{backupFilePath}'";
                    using (var command = new SqlCommand(query, connection))
                    {
                        await connection.OpenAsync();
                        await command.ExecuteNonQueryAsync();
                    }
                }

                return Ok(backupFilePath);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpPost]
        [Route("backup-postgresql")]
        public async Task<IActionResult> BackupPostgreSql()
        {
            try
            {
                var backupFolder = Path.Combine(Directory.GetCurrentDirectory(), "Backups");
                if (!Directory.Exists(backupFolder))
                    Directory.CreateDirectory(backupFolder);

                var backupFilePath = Path.Combine(backupFolder, $"pg_backup_{DateTime.Now:yyyyMMddHHmmss}.sql");
                var connectionString = _configuration.GetConnectionString("PgSqlConnection");

                var command = $"postgres --dbname={connectionString} --file={backupFilePath}";
                var processStartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = new Process { StartInfo = processStartInfo })
                {
                    process.Start();
                    await process.WaitForExitAsync();
                    if (process.ExitCode != 0)
                    {
                        var error = await process.StandardError.ReadToEndAsync();
                        return StatusCode(500, $"Error: {error}");
                    }
                }

                return Ok(backupFilePath);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpGet]
        [Route("download")]
        public async Task<IActionResult> DownloadBackup([FromQuery] string fileName)
        {
            try
            {
                var backupFolder = Path.Combine(Directory.GetCurrentDirectory(), "Backups");
                var filePath = Path.Combine(backupFolder, fileName);

                if (!System.IO.File.Exists(filePath))
                {
                    return NotFound("File not found.");
                }

                var memory = new MemoryStream();
                using (var stream = new FileStream(filePath, FileMode.Open))
                {
                    await stream.CopyToAsync(memory);
                }
                memory.Position = 0;

                return File(memory, "application/octet-stream", fileName);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpPost]
        [Route("upload")]
        public async Task<IActionResult> UploadBackup([FromForm] IFormFile file)
        {
            if (file == null || file.Length == 0)
                return BadRequest("No file uploaded.");

            var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
            if (string.IsNullOrEmpty(ext) || Array.IndexOf(permittedExtensions, ext) < 0)
                return BadRequest("Invalid file type.");

            var uploadFolder = Path.Combine(Directory.GetCurrentDirectory(), "Uploads");
            if (!Directory.Exists(uploadFolder))
                Directory.CreateDirectory(uploadFolder);

            var filePath = Path.Combine(uploadFolder, file.FileName);

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            return Ok("File uploaded successfully.");
        }

        [HttpPost]
        [Route("restore-sqlserver")]
        public async Task<IActionResult> RestoreSqlServerBackup([FromForm] IFormFile file)
        {
            if (file == null || file.Length == 0)
                return BadRequest("No file uploaded.");

            var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
            if (string.IsNullOrEmpty(ext) || Array.IndexOf(permittedExtensions, ext) < 0)
                return BadRequest("Invalid file type.");

            var uploadFolder = Path.Combine(Directory.GetCurrentDirectory(), "Uploads");
            if (!Directory.Exists(uploadFolder))
                Directory.CreateDirectory(uploadFolder);

            var filePath = Path.Combine(uploadFolder, file.FileName);

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            try
            {
                var connectionString = _configuration.GetConnectionString("DefaultConnection");

                using (var connection = new SqlConnection(connectionString))
                {
                    var query = $"RESTORE DATABASE [mydb] FROM DISK = '{filePath}' WITH REPLACE";
                    using (var command = new SqlCommand(query, connection))
                    {
                        await connection.OpenAsync();
                        await command.ExecuteNonQueryAsync();
                    }
                }

                return Ok("Database restored successfully.");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }

        [HttpPost]
        [Route("restore-postgresql")]
        public async Task<IActionResult> RestorePostgreSqlBackup([FromForm] IFormFile file)
        {
            if (file == null || file.Length == 0)
                return BadRequest("No file uploaded.");

            var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
            if (string.IsNullOrEmpty(ext) || Array.IndexOf(permittedExtensions, ext) < 0)
                return BadRequest("Invalid file type.");

            var uploadFolder = Path.Combine(Directory.GetCurrentDirectory(), "Uploads");
            if (!Directory.Exists(uploadFolder))
                Directory.CreateDirectory(uploadFolder);

            var filePath = Path.Combine(uploadFolder, file.FileName);

            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }

            try
            {
                var connectionString = _configuration.GetConnectionString("PgSqlConnection");

                var command = $"psql --dbname={connectionString} --file={filePath}";
                var processStartInfo = new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = $"/c {command}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = new Process { StartInfo = processStartInfo })
                {
                    process.Start();
                    await process.WaitForExitAsync();
                    if (process.ExitCode != 0)
                    {
                        var error = await process.StandardError.ReadToEndAsync();
                        return StatusCode(500, $"Error: {error}");
                    }
                }

                return Ok("Database restored successfully.");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error: {ex.Message}");
            }
        }
    }

}

