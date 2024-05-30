using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;
using Ocelot.DependencyInjection;
using Ocelot.Middleware;

var builder = WebApplication.CreateBuilder(args);

// Add Ocelot configuration
builder.Configuration.AddJsonFile("ocelot.json", optional: false, reloadOnChange: true);

// Register CORS services
builder.Services.AddCors();

// Register Ocelot services
builder.Services.AddOcelot(builder.Configuration);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseCors(policy =>
    {
        policy.WithOrigins("https://localhost:7072")
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
}

// Use Ocelot middleware
await app.UseOcelot();

// Map controllers if you have any
app.MapControllers();

app.Run();
