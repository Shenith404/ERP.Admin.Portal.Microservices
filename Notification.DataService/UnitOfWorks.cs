
using Microsoft.Extensions.Logging;
using Notification.DataService.IRepository;


namespace Notification.DataService.Repository
{
    public class UnitOfWorks : IUnitOfWorks ,IDisposable
    {

        private readonly PgsqlDbContext _context;


        public INotificationRepository Notifications { get; private set; }

        public UnitOfWorks(PgsqlDbContext context, ILoggerFactory loggerFactory)
        {
            _context = context;
            var logger = loggerFactory.CreateLogger("Notificationlogs");
            Notifications = new NotificationRepository(logger,_context);

        }

        public async Task<bool> CompleteAsync()
        {
            var result = await _context.SaveChangesAsync();

            return result>0;
        }

        public void Dispose() { 
            _context.Dispose();
            }
    }
}
