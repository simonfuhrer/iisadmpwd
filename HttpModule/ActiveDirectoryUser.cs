using System;
using System.Collections.Generic;
using System.Text;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Collections;
using System.Security.Principal;
using ActiveDs;
using System.IO;
using System.Threading;
namespace IISADMPWD
{
    public class ActiveDirectoryUser
    {
        #region Private Variables
        private DirectoryEntry user;
        private string baseDN;
        private string configDN;
        public string constructedupn;
        #endregion

        #region Getter/Setter
        #endregion

        #region Enumerations
        [Flags]
        internal enum AdsUserFlags
        {
            Script = 1,						  // 0x1
            AccountDisabled = 2,				 // 0x2
            HomeDirectoryRequired = 8,		   // 0x8 
            AccountLockedOut = 16,			   // 0x10
            PasswordNotRequired = 32,			// 0x20
            PasswordCannotChange = 64,		   // 0x40
            EncryptedTextPasswordAllowed = 128,  // 0x80
            TempDuplicateAccount = 256,		  // 0x100
            NormalAccount = 512,				 // 0x200
            InterDomainTrustAccount = 2048,	  // 0x800
            WorkstationTrustAccount = 4096,	  // 0x1000
            ServerTrustAccount = 8192,		   // 0x2000
            PasswordDoesNotExpire = 65536,	   // 0x10000
            MnsLogonAccount = 131072,			// 0x20000
            SmartCardRequired = 262144,		  // 0x40000
            TrustedForDelegation = 524288,	   // 0x80000
            AccountNotDelegated = 1048576,	   // 0x100000
            UseDesKeyOnly = 2097152,			  // 0x200000
            DontRequirePreauth = 4194304,		 // 0x400000
            PasswordExpired = 8388608,		   // 0x800000
            TrustedToAuthenticateForDelegation = 16777216, // 0x1000000
            NoAuthDataRequired = 33554432		// 0x2000000

        }
        #endregion

        #region Constructors

        private string ConverttoUPN(string username, string domain)
        {
            string convertedusername;
            string converteddomainname;
            if (username.Contains(@"\"))
            {
                int index = username.IndexOf(@"\");
                convertedusername = username.Substring(index + 1, username.Length - index - 1);
                converteddomainname = username.Substring(0, index);
                if (!converteddomainname.Contains("."))
                {
                    converteddomainname = GetDNSDomaiNamefromNetbios(converteddomainname);

                }

            }
            else if (username.Contains("@"))
            {
                int index = username.IndexOf("@");
                convertedusername = username.Substring(0, index);
                converteddomainname = username.Substring(index + 1);
            }
            else
            {
                convertedusername = username;
                converteddomainname = domain;
                if (!converteddomainname.Contains("."))
                {
                    converteddomainname = GetDNSDomaiNamefromNetbios(converteddomainname);

                }
            }
            return convertedusername + "@" + converteddomainname;
        }



        public ActiveDirectoryUser(string username,string domain)
		{
			//
			// TODO: Add constructor logic here
			//
            DirectoryEntry rootdse = new DirectoryEntry("GC://RootDSE");
            baseDN = rootdse.Properties["rootDomainNamingContext"].Value.ToString();
            configDN = rootdse.Properties["configurationNamingContext"].Value.ToString() ;
            constructedupn = ConverttoUPN(username, domain);
            try
            {

                DirectoryEntry domaindn = new DirectoryEntry("GC://" + baseDN);
                DirectorySearcher searcher = new DirectorySearcher(domaindn);

                string filter = String.Format("(&(objectCategory=person)(objectClass=user)(userPrincipalName={0}))", constructedupn);
                searcher.Filter = filter;
                searcher.CacheResults = false;
                searcher.SearchScope = SearchScope.Subtree;

                // Find user

                SearchResult result = searcher.FindOne();
                if (result != null)
                {
                    string newpath = result.GetDirectoryEntry().Path.Replace("GC","LDAP");
                    user = new DirectoryEntry(newpath);
                }
                else
                {
        
                }

            }
            catch (Exception ex)
            {
                
                //throw new Exception("Error" + ex.Message);

            }
		}        
        #endregion

        #region Methods


        public string GetDNSDomaiNamefromNetbios(string netbios)
        {
            string netbiosName = netbios;
            // Search for an object that is of type crossRefContainer.
            DirectoryEntry configde = new DirectoryEntry("LDAP://" + configDN);
            DirectorySearcher searcher = new DirectorySearcher(configde);
            searcher.Filter = string.Format("(&(objectcategory=Crossref)(netBIOSName={0}))", netbios);
            searcher.PropertiesToLoad.Add("dnsRoot");

            SearchResultCollection results = searcher.FindAll();
            if (results.Count > 0)
            {
                ResultPropertyValueCollection rpvc = results[0].Properties["dnsRoot"];
                
                netbiosName = rpvc[0].ToString();
            }
            return netbiosName;
        }



        public bool AccountExists()
        {
            if (user != null){
                return true;
            }
            return false;
        }


        public bool AccountLocked()
        {
   
            //user is a DirectoryEntry for our user account
            string attrib = "msDS-User-Account-Control-Computed";

            //this is a constructed attrib
            user.RefreshCache(new string[] { attrib });

            const int UF_LOCKOUT = 0x0010;

            int flags =
              (int)user.Properties[attrib].Value;

            if (Convert.ToBoolean(flags & UF_LOCKOUT))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public bool PasswordExpired()
        {
            return ((PasswordExpiresDate()).AddDays(-5) < DateTime.Now);
        }

        public bool PasswordChangeRequired()
        {
            IADsLargeInteger lastSetLongInt = (IADsLargeInteger)user.Properties["pwdLastSet"].Value;
            long filetime = lastSetLongInt.HighPart * 4294967296 + lastSetLongInt.LowPart;
            return (filetime == 0);
        }

        public bool PasswordDoesNotExpire()
        {
            return checkAdsFlag(AdsUserFlags.PasswordDoesNotExpire);
        }

        public bool AccountDisabled()
        {
            return checkAdsFlag(AdsUserFlags.AccountDisabled);
        }

        public string FullName()
        {
            return user.Name.Substring(3);
        }

        public DateTime PasswordExpiresDate()
        {

            IADsLargeInteger lastSetLongInt = (IADsLargeInteger)user.Properties["pwdLastSet"].Value;
            long filetime = lastSetLongInt.HighPart * 4294967296 + lastSetLongInt.LowPart;
            DateTime PasswordLastSet = DateTime.FromFileTime(filetime);

            return PasswordLastSet.AddDays(passwordMaxAge());
        }



        private bool checkFlag(AdsUserFlags flagValue)
        {
            int userFlags = (int)user.Properties["userAccountControl"].Value;
            int flagValueInt = Convert.ToInt16(((int)flagValue).ToString(), 8);

            //int i = 32; // for example
            byte[] ba = BitConverter.GetBytes((int)flagValue);
            BitArray flagBitArray = new BitArray(ba);

            ba = BitConverter.GetBytes(flagValueInt);
            BitArray flagValueArray = new BitArray(ba);

            for (int i = 0; i < 32; i++)
            {
                if (flagBitArray[i] && flagValueArray[i])
                    return true;
            }

            return false;
        }

        private bool checkAdsFlag(AdsUserFlags flagToCheck)
        {
            AdsUserFlags userFlags = (AdsUserFlags)
                user.Properties["userAccountControl"].Value;

            return userFlags.ToString().Contains(flagToCheck.ToString()); // userFlags == flagToCheck;
        }

        private int passwordMaxAge()
        {

           // Domain domain = Domain.GetCurrentDomain();
            return 30;

            //return 0; // Used to test label
        }
        #endregion
    }
}