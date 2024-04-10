using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Notification.Core.Entity
{
    public class BaseEntity
    {

        [Key]
        public Guid Id { get; set; }
        public DateTime AddedDate { get; set; } = DateTime.UtcNow;
        public DateTime UpdateDate { get; set; } = DateTime.UtcNow;
        public int Status { get; set; } //Delete or not
    }
}
