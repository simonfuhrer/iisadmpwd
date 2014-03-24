using System;
using System.Collections.Generic;
using System.Text;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Collections;
using ActiveDs;
using System.Security.Principal;

namespace HttpModule
{
    public class ActiveDirectoryUser
    {
        #region Private Variables
        private DirectoryEntry user;
        private string baseDN;
        #endregion

        #region Getter/Setter
        public string m_AD_techuser { get; set; }
        public string m_AD_techuserpw { get; set; }
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
    
        public ActiveDirectoryUser()
		{
			//
			// TODO: Add constructor logic here
			//
            DirectoryEntry rootdse = new DirectoryEntry("LDAP://RootDSE", m_AD_techuser, m_AD_techuserpw);
            baseDN = rootdse.Properties["defaultnamingcontext"][0].ToString();

		}        
        #endregion

        #region Methods

        public void ADUser(string userName)
        {
            try
            {

                user = new DirectoryEntry("LDAP://" + baseDN, m_AD_techuser, m_AD_techuserpw);
                DirectorySearcher searcher = new DirectorySearcher(user);

                searcher.Filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=" + userName + "))";
                searcher.CacheResults = false;

                // Find user

                SearchResult result = searcher.FindOne();
                user = result.GetDirectoryEntry();

            }
            catch (Exception ex)
            {
                //throw new Exception("Error" + ex.Message);

            }
        }


        public bool AccountExists(string name)
        {
            bool bRet = false;

            try
            {
                NTAccount acct = new NTAccount(name);
                SecurityIdentifier id = (SecurityIdentifier)acct.Translate(typeof(SecurityIdentifier));

                bRet = id.IsAccountSid();
            }
            catch (IdentityNotMappedException)
            {
                /* Invalid user account */
            }

            return bRet;
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