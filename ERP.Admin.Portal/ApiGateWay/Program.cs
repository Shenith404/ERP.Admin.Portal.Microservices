using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using ApiGateWay;

var builder = WebApplication.CreateBuilder(args);

// Add Ocelot configuration
builder.Configuration.AddJsonFile("ocelot.json", optional: false, reloadOnChange: true);

// Register CORS services
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins("https://localhost:7072")
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

builder.Services.AddCustomJwtAuthenticaion();



// Add authorization with policies
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminPolicy", policy => policy.RequireRole("Admin"));
    options.AddPolicy("LecturePolicy", policy => policy.RequireRole("Lecture"));
    options.AddPolicy("StaffPolicy", policy => policy.RequireRole("Staff"));
    options.AddPolicy("RegularPolicy", policy => policy.RequireRole("Reguler")); 
    options.AddPolicy("DepartmentAcademicPolicy", policy => policy.RequireRole("Admin", "Lecture", "Staff"));
});



// Register Ocelot services
builder.Services.AddOcelot(builder.Configuration);

var app = builder.Build();

// Use CORS middleware
app.UseCors();

app.UseAuthentication();
app.UseAuthorization();

// Use Ocelot middleware
await app.UseOcelot();

// Map controllers if you have any
app.MapControllers();

app.Run();
