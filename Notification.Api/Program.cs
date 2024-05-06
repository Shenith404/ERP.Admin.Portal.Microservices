using Microsoft.EntityFrameworkCore;
using Notification.DataService;
using Notification.DataService.Repository;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddSwaggerGen();
builder.Services.AddControllers();
builder.Services.AddScoped<IUnitOfWorksNotification, UnitOfWorksNotification>();

//configure Automapper
builder.Services.AddAutoMapper(AppDomain.CurrentDomain.GetAssemblies());
builder.Services.AddDbContextFactory<PgsqlDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("PgSqlConnection")));
 
var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
// Configure the HTTP request pipeline.

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
