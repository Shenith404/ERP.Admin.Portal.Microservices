using Authentication.Api.MappingProfiles;
using Authentication.DataService;
using Authentication.DataService.IConfiguration;
using Authentication.jwt;
using EmailSender.SendEmail;
using ERP.Authentication.Core.Entity;
using ERP.Authentication.Jwt;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Net.Http.Headers;
using Notification.DataService;
using Notification.DataService.IRepository;
using Notification.DataService.Repository;
using Microsoft.Extensions.Logging;

var builder = WebApplication.CreateBuilder(args);

// Configure logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();
builder.Logging.AddEventSourceLogger();

// Add services to the container.
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddScoped<IUnitOfWorks, UnitOfWorks>();
builder.Services.AddScoped<IJwtTokenHandler, JwtTokenHandler>();
builder.Services.AddScoped<ISendEmail, SendEmail>();

// Configure Automapper
builder.Services.AddAutoMapper(typeof(DomainToResponse));
builder.Services.AddAutoMapper(typeof(ResponseToDomain));

builder.Services.AddIdentityCore<UserModel>(options =>
{
    options.SignIn.RequireConfirmedAccount = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireDigit = true;
    options.User.RequireUniqueEmail = true;
    options.Lockout.AllowedForNewUsers = true;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);
    options.Lockout.MaxFailedAccessAttempts = 5;
})
.AddRoles<IdentityRole>()
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();

builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromDays(1);
});

builder.Services.AddDbContext<AppDbContext>(o => o.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddCustomJwtAuthenticaion();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseCors(
        policy =>
        {
            policy.WithOrigins("https://localhost:7072")
             .AllowAnyHeader()
             .AllowAnyMethod()
             .WithHeaders(HeaderNames.ContentType);
        });
}

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
