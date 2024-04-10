

namespace Notification.Core.Entity
{
    public class Notification : BaseEntity
    {
        public string Titile { get; set; } =string.Empty;   
        public string Content { get; set; }=string.Empty;
        public Guid  ? ReceiverId { get; set; }
        public bool ReadStatus { get; set; } = false;
        

    }
}
