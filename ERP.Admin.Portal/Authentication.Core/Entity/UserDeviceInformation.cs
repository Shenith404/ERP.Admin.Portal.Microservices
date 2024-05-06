using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.Core.Entity
{
    public class UserDeviceInformation 
    {
        [Key]
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public Guid Id { get; set; }

        public Guid UserId { get; set; }

        public string ? UserAgentDetails { get; set; }

        public DateTime  LoginDate { get; set; } = DateTime.Now;

        public string ? IP { get; set; }
        
        public int Status { get; set; }





    }
}
