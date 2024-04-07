﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EmailSender.SendEmail
{
    public interface ISendEmail
    {
        Task<bool> SendVerificationEmailAsync(string email, string verificationLink);

    }
}
