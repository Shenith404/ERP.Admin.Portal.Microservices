﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.Core.DTOs
{
    public class TwoFAVerificatinRequestDTO
    {
        public string Email {  get; set; }

        public string Code { get; set; }
    }
}
