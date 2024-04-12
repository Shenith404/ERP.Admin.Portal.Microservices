namespace Notification.Core.Entity
{
    public class NotificationModel : BaseEntity
    {
        public string Title { get; set; } =string.Empty;   
        public string Content { get; set; }=string.Empty;
        public Guid  ? ReceiverId { get; set; }
        public bool ReadStatus { get; set; } 
        public int Priority { get; set; } 
        public string ? Link { get; set; }
        public NotificationType Type { get; set; }


    }

    public enum NotificationType
    {
        Success, //green
        Error, //red
        Warning, //yellow
        Info //blue
    }

}
