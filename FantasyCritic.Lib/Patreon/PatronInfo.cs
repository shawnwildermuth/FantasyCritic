﻿using CSharpFunctionalExtensions;
using FantasyCritic.Lib.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FantasyCritic.Lib.Patreon
{
    public class PatronInfo
    {
        public PatronInfo(FantasyCriticUser user, bool isPlusUser, Maybe<string> donorName)
        {
            User = user;
            IsPlusUser = isPlusUser;
            DonorName = donorName;
        }

        public FantasyCriticUser User { get; }
        public bool IsPlusUser { get; }
        public Maybe<string> DonorName { get; }
    }
}