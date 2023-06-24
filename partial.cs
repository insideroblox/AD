using Roblox.EventLog;
using Roblox.EventLog.Windows;
using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Runtime.InteropServices;

namespace Roblox.ActiveDirectory
{
    public static class ActiveDirectoryAccessVerifier
    {
        /// <summary>
        ///  Logger Instance.
        /// </summary>
        private static ILogger _Logger = new Logger(
            global::Roblox.ActiveDirectory.Properties.Settings.Default.LogName,
            () => global::Roblox.ActiveDirectory.Properties.Settings.Default.LogLevel,
            true
        ) { LogClassAndMethodName = true };

        /// <summary>
        /// Authenticates credentials for AD (Active Directory) domain.
        /// </summary>
        /// <param name="userName">The username WITHOUT the Domain Qualifier</param>
        /// <param name="password">The password</param>
        /// <param name="domain">The domain</param>
        /// <returns></returns>
        public static bool VerifyActiveDirectoryPassword(string userName, string password, string domain)
        {
            if (Properties.Settings.Default.DebugHardcodedCredentials)
            {
                if (userName == "roblox" && password == "debug")
                    return true;
            }

            try
            {
                _Logger.LifecycleEvent("Attempting to authenticate user '{0}' for domain '{1}'", userName, domain);
                using (PrincipalContext context = new PrincipalContext(ContextType.Domain, domain))
                {
                    // check if the user exists in AD
                    if (!UserExists(userName, context))
                    {
                        _Logger.Warning("User '{0}' does not exist in Active Directory", userName);
                        return false;
                    }

                    // get the user's distinguished name (DN) in AD
                    string userDn = GetUserDn(userName, context);
                    string path = "LDAP://" + userDn;

                    // create a new DirectoryEntry object for the user
                    _Logger.LifecycleEvent("Got path '{0}' for doamin '{1}'", path, domain);
                    using (DirectoryEntry userEntry = new DirectoryEntry(path, userName, password, AuthenticationTypes.Secure))
                    {
                        if (userEntry != null)
                        {
                            userEntry.RefreshCache();

                            // check password expiration status
                            if (userEntry.Properties["PasswordExpirationDate"]?.Value != null)
                            {
                                DateTime passwordExpiration = (DateTime)userEntry.Properties["PasswordExpirationDate"].Value;
                                if (passwordExpiration <= DateTime.Now)
                                {
                                    _Logger.Warning("Password for user '{0}' has expired", userName);
                                    return false;
                                }
                            }

                            // check if password is expired but user is allowed to change password
                            if (userEntry.Properties["AllowPasswordChange"]?.Value != null && userEntry.Properties["PasswordLastSet"]?.Value != null)
                            {
                                bool allowPasswordChange = Convert.ToBoolean(userEntry.Properties["AllowPasswordChange"].Value);
                                if (allowPasswordChange && (DateTime)userEntry.Properties["PasswordLastSet"].Value == DateTime.MinValue)
                                {
                                    _Logger.Warning("Password for user '{0}' has expired but user is allowed to change password.", userName);
                                    return false;
                                }
                            }
                        }
                    }
                }

                _Logger.LifecycleEvent("User '{0}' is authenticated", userName);
                return true;
            }
            catch (DirectoryServicesCOMException ex)
            {
                _Logger.Error(ex);
                return false;
            }
            catch (PrincipalException ex)
            {
                _Logger.Error(ex);
                return false;
            }
            catch (COMException ex)
            {
                if (ex.Message.Contains("Invalid"))
                    return false;
                _Logger.Error(ex);
                throw;
            }
            catch (Exception ex)
            {
                _Logger.Error(ex);
                throw;
            }
        }

        /// <summary>
        /// Checks if user exists in AD (Active Directory)
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        private static bool UserExists(string userName, PrincipalContext context)
        {
            UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, userName);
            return userPrincipal != null;
        }

        /// <summary>
        /// Get the users DN (Distinguished Name)
        /// </summary>
        /// <param name="userName">The username</param>
        /// <param name="context">The <see cref="PrincipalContext"/>Context</param>
        /// <returns>The DN (Distinguished Name)</returns>
        /// <exception cref="ArgumentException"></exception>
        private static string GetUserDn(string userName, PrincipalContext context)
        {
            UserPrincipal userPrincipal = UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, userName);
            if (userPrincipal == null)
            {
                throw new ArgumentException($"User '{userName}' does not exist in Active Directory.");
            }

            return userPrincipal.DistinguishedName;
        }

    }
}
