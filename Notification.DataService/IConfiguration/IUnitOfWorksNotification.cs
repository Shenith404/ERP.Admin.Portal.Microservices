using Notification.DataService.IRepository;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Notification.DataService.Repository
{
    public interface IUnitOfWorksNotification
    {
        INotificationRepository Notifications { get; }

        Task<bool> CompleteAsync();
    }
}
