using Notification.Core.Entity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Notification.DataService.IRepository
{
    public interface INotificationRepository : IGenericRepository<NotificationModel>
    {
        Task<bool> MarkNotificationAsReadAsync(Guid id);

        Task<bool> MarkAllNotificationAsReadAsync(Guid userId);

    }
}
