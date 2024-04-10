using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Notification.Core.DTOs
{
    public class CreateNotificationDTO
    {
        public string Titile { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public Guid ? ReceiverId { get; set; }
        public bool ReadStatus { get; set; } = false;
    }
}
