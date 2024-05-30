
using System.ComponentModel.DataAnnotations;


namespace Announcement_.core.Entity
{
    public class Announcement : BaseEntity
    {
        public string Title { get; set; } = string.Empty;

        public  string Content { get; set; } = string.Empty;

        public string Audience { get; set; }= string.Empty;

        public AnnouncementType Type { get; set; }

        public DateTime? ExpirationDate { get; set; } // Expiration date of the announcement
        
        public UrgencyLevel UrgencyLevel { get; set; }

        public ICollection<string> RelatedLinks { get; set; } = [];// List of related links
        
        public ICollection<string> Attachments { get; set; } = []; // List of attachment file paths or URLs

        public string Publisher { get; set; } = string.Empty; // Contact person for the announcement
                                                                  // 
        public DateTime? DisplayUntil { get; set; } // Display until date

        public bool AcknowledgmentRequired { get; set; }

    }

    public enum AnnouncementType
    {
        Academic, Events, Emergency, GeneralNews, Administrative
    }

    public enum UrgencyLevel
    {
        High, Medium, Low
    }




}
