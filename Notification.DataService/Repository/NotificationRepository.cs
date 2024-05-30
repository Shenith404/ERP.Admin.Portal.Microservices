using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Notification.Core.Entity;
using Notification.DataService.IRepository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Notification.DataService.Repository
{
    public class NotificationRepository : GenericRepository<NotificationModel>, INotificationRepository
    {
        public NotificationRepository(ILogger logger, PgsqlDbContext context) : base(logger, context)
        {
        }

        public override async Task<IEnumerable<NotificationModel>> GetAll(string searchString, Guid receiver)
        {
            try
            {
                var query = dbSet
                    .Where(x => x.Status == 1 && x.ReceiverId == receiver).OrderByDescending(x => x.AddedDate)
                    .AsNoTracking();

                if (!string.IsNullOrWhiteSpace(searchString))
                {

                    
                    query = query.Where(u =>
                        u.Title!.Contains(searchString) ||
                        u.Content!.Contains(searchString)
                    );
                }

                var searchResult = await query.ToListAsync();

                return searchResult;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "{Repo} GetAll method has generated Error", typeof(NotificationModel));
                return Enumerable.Empty<NotificationModel>();
            }
        }


        public async Task<bool> MarkAllNotificationAsReadAsync(Guid userId)
        {
            var unReadedNotifications = await dbSet.Where(x => x.ReadStatus == false && x.Status==1 && x.ReceiverId==userId)
                    .ToListAsync();
            foreach (var notification in unReadedNotifications)
            {
                notification.ReadStatus = true;
                dbSet.Update(notification);  
            }
            return true;
        }


        public async Task<bool> MarkNotificationAsReadAsync(Guid id)
        {
            var notification = await dbSet.FindAsync(id);
            if (notification != null)
            {
                notification.ReadStatus=true;
                dbSet.Update(notification);
                return true;
            }

            return  false;
        }
    }
}
