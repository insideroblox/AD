 private static ILogger _Logger = new Logger(
            global::Roblox.ActiveDirectory.Properties.Settings.Default.LogName,
            () => global::Roblox.ActiveDirectory.Properties.Settings.Default.LogLevel,
            true
        ) 
        {
            LogClassAndMethodName = true,
        };

        public static bool VerifyActiveDirectoryPassword(string userName, string password, string domain)
        {
            try
            {
                _Logger.LifecycleEvent("Attempting to authenticate user '{0}' for domain '{1}'.", userName, domain);
                using (PrincipalContext context = new PrincipalContext(ContextType.Domain, domain))
                {
                    // check if the user exists in AD
                    if (!UserExists(userName, context))
                    {
                        _Logger.Warning("User '{0}' does not exist in Active Directory.", userName);
                        return false;
                    }

                    // get the user's distinguished name (DN) in AD
                    string userDn = GetUserDn(userName, context);
                    string path = "LDAP://" + userDn;
