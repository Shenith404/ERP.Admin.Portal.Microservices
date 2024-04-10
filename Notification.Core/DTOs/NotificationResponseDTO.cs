using Notification.Core.Entity;

namespace Notification.Core.DTOs
{
    public class NotificationResponseDTO : BaseEntity
    {
        public string Titile { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public Guid? ReceiverId { get; set; }
        public bool ReadStatus { get; set; } = false;


    }
}
