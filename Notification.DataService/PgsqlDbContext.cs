using Microsoft.EntityFrameworkCore;
using Notification.Core.Entity;

namespace Notification.DataService
{
    public class PgsqlDbContext : DbContext
    {
        public PgsqlDbContext(DbContextOptions<PgsqlDbContext> options) : base(options) { }

        public DbSet<NotificationModel> Notifications { get; set; }
    }
}
