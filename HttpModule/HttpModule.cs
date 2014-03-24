using System;
using System.Collections.Generic;
using System.Text;
using System.Web;
using System.IO;
using System.Collections;
using System.Configuration;
using System.Security;
using System.Web.Security;
using System.Security.Principal;
using System.Threading;
using System.Net.NetworkInformation;
using System.DirectoryServices;


namespace HttpModule
{
    public class IISADMPWDHttpModule : IHttpModule
    {
        #region Private Properties
        private HttpApplication app;
        private bool DoLogging = false;
        private int pwdmustchangeretcode = 306;
        private string LogFile;
        private string TechUser;
        private string Techpwd;
        private bool checkpwdmustchange = false;
        private bool checkpwdexpired = false;
        private bool checkpwdlokedout = false;
        private bool checkuseraccountstatus = false;
        private bool checkpassworddoesnotexpire = false;
        #endregion

        #region Constructor/ Dispose
        /// 
        /// Required by the interface IHttpModule
        /// 
        public IISADMPWDHttpModule()
        {
        }

        public void Dispose()
        {
            Logging("::Dispose");
        }
        #endregion

        #region Initialization
        /// 
        /// Required by the interface IHttpModule
        /// I also wire up the Begin Request event.
        /// 
        public void Init(HttpApplication Appl)
        {
            Appl.BeginRequest += new System.EventHandler(OnBeginRequest);
            Appl.EndRequest += new EventHandler(OnEndRequest);
            Appl.AcquireRequestState += new EventHandler(Appl_AcquireRequestState);
            Appl.ReleaseRequestState += new EventHandler(Appl_ReleaseRequestState);
            Appl.AuthenticateRequest += new EventHandler(Appl_AuthenticateRequest);
            Appl.PreSendRequestContent += new EventHandler(Appl_PreSendRequestContent);
            Appl.AuthorizeRequest += new EventHandler(Appl_AuthorizeRequest);
            Appl.PostAuthenticateRequest += new EventHandler(OnPostAuthenticateRequest);
            // Appl.Error += new EventHandler(Appl_Context_Error);

        }
        #endregion

        #region HttpModule Event Handlers
        void Appl_Context_Error(object sender, EventArgs e)
        {
            Logging("Appl_Context_Error");
        }

        void OnPostAuthenticateRequest(object sender, EventArgs e)
        {
            Logging("Appl_PreSendRequestContent");
        }

        void Appl_AuthorizeRequest(object sender, EventArgs e)
        {
            Logging("Appl_PreSendRequestContent");
        }

        void Appl_PreSendRequestContent(object sender, EventArgs e)
        {
            Logging("Appl_PreSendRequestContent");
        }

        void Appl_AuthenticateRequest(object sender, EventArgs e)
        {
            Logging("::AuthenticateRequest");
            HttpApplication app = (HttpApplication)sender;
            HttpContext context = app.Context;
            string authorization = app.Request.Headers["Authorization"];

            if (context.Request.IsAuthenticated)
            {
                Logging("Appl_AuthReq: Is Authenticated");
                return;
            }

        }

        void Appl_ReleaseRequestState(object sender, EventArgs e)
        {
            Logging("::Appl_ReleaseRequestState");
        }

        void Appl_AcquireRequestState(object sender, EventArgs e)
        {
            Logging("::Appl_AcquireRequestState");
        }

        public void OnBeginRequest(object sender, EventArgs e)
        {
            Logging("::OnBeginRequest");
            HttpApplication app = (HttpApplication)sender;
            HttpContext context = app.Context;
            string userid2;
            Initialize(sender);

            if (context.Request.IsAuthenticated)
            {
                Logging("Is Authenticated");
                return;
            }

            string authorization = app.Request.Headers["Authorization"];

            #region base64 converter etc
            if ((authorization == null) || (authorization.Length == 0))
            {
                Logging("BeginRequest: Authorization Header not present");
                return;
            }

            if (authorization.StartsWith("NTLM"))
            {
                Logging("BeginRequest: Headers Start with NTLM");
                byte[] msg = Convert.FromBase64String(authorization.Substring(5));
                int off = 0, length, offset;

                if (msg[8] == 1)
                {
                    Logging("BeginRequest:msg_offset_8 == 1");
                }
                else if (msg[8] == 3)
                {
                    Logging("BeginRequest:msg_offset_8 == 3 Header=" + authorization);
                    //Encoding le = new UnicodeEncoding(false, true); // UTF-16LE

                    off = 30;
                    length = msg[off + 17] * 256 + msg[off + 16];
                    offset = msg[off + 19] * 256 + msg[off + 18];
                    String remoteHost = Encoding.Unicode.GetString(msg, offset, length);
                    Logging("RemoteHost=" + remoteHost);


                    length = msg[off + 1] * 256 + msg[off];
                    offset = msg[off + 3] * 256 + msg[off + 2];
                    String domain = Encoding.Unicode.GetString(msg, offset, length);
                    Logging("Domain=" + domain);

                    length = msg[off + 9] * 256 + msg[off + 8];
                    offset = msg[off + 11] * 256 + msg[off + 10];
                    userid2 = Encoding.Unicode.GetString(msg, offset, length);
                    Logging("username=" + userid2);

                    Logging("Starting Directory Mgmt Class");
                   
                    string plainuser = PlainUserName(userid2);
                    Logging("PlainUsername: " + plainuser);

                    ActiveDirectoryUser ADclsuser = new ActiveDirectoryUser();
                    ADclsuser.m_AD_techuser = TechUser;
                    ADclsuser.m_AD_techuserpw = Techpwd;
                             

                    if (ADclsuser.AccountExists(plainuser))
                    {
                        ADclsuser.ADUser(plainuser);
                        checkpassworddoesnotexpire = ADclsuser.PasswordDoesNotExpire();
                        checkpwdmustchange = ADclsuser.PasswordChangeRequired();
                        checkpwdexpired = ADclsuser.PasswordExpired();
                        checkpwdlokedout = ADclsuser.AccountLocked();
                        checkuseraccountstatus = ADclsuser.AccountDisabled();
                        Logging("Status: PasswordChangeRequired =  " + checkpwdmustchange.ToString());
                        Logging("Status: PasswordExpired =  " + checkpwdexpired.ToString());
                        Logging("Status: AccountLocked =  " + checkpwdlokedout.ToString());
                        Logging("Status: AccountDisabled =  " + checkuseraccountstatus.ToString());
                    }
                    else
                    {
                        Logging("User " + plainuser + " dont exist");
                        return;
                    }

                }

            }
            #endregion
        }


        public void OnEndRequest(object sender, EventArgs e)
        {
            Logging("::OnEndRequest");
            HttpApplication app = (HttpApplication)sender;

            if (checkpassworddoesnotexpire)
            {
                Logging("Password does not expires");
                return;
            }

            if (checkuseraccountstatus)
            {
                //throw new HttpException(pwdmustchangeretcode, "Account Disabled");
                ResponseStatus(app, 1, "Account disbaled");
                return;
            }

            if (checkpwdmustchange)
            {
                //throw new HttpException(pwdmustchangeretcode, "PasswordChangeRequired");
                ResponseStatus(app, 2, "PasswordChangeRequired");
                return;
            }

            if (checkpwdlokedout)
            {
                //throw new HttpException(pwdmustchangeretcode, "AccountLocked");
                ResponseStatus(app, 3, "AccountLocked");
                return;
            }

            if (checkpwdexpired)
            {
                //throw new HttpException(pwdmustchangeretcode, "PasswordExpired");
                ResponseStatus(app, 4, "PasswordExpired");
                return;
            }

        }

        #endregion

        #region Private Methods

        private void Initialize(object sender)
        {
            Logging("OnBeginRequest_1_initialize");
            app = (HttpApplication)sender;
            checkpwdmustchange = false;
            checkpwdexpired = false;
            checkpwdlokedout = false;
            checkuseraccountstatus = false;

            IPGlobalProperties ipp = IPGlobalProperties.GetIPGlobalProperties();
            string Tracing = ConfigurationManager.AppSettings["Tracing"].ToLower();
            TechUser = ConfigurationManager.AppSettings["TechUserAD"].ToLower();
            Techpwd = ConfigurationManager.AppSettings["TechpwdAD"];
            string pwdmustchangeretcode_str = ConfigurationManager.AppSettings["PwdMustChangeRetCode"].ToLower();
            pwdmustchangeretcode = int.Parse(pwdmustchangeretcode_str);
            DoLogging = bool.Parse(Tracing);
            LogFile = ConfigurationManager.AppSettings["LogFile"];

        }


        private static string PlainUserName(string username)
        {
            if (username.Contains(@"\"))
            {
                int index = username.IndexOf(@"\");
                return username.Substring(index + 1, username.Length - index - 1);
            }
            else if (username.Contains("@"))
            {
                int index = username.IndexOf("@");
                return username.Substring(0, index);
            }
            else
            {
                return username;
            }
        }

        private void Logging(string Message)
        {
            try
            {
                if (DoLogging)
                {
                    File.AppendAllText(LogFile, DateTime.Now.ToLongTimeString() + ": " + Message + Environment.NewLine);
                }
            }
            catch (SystemException se)
            {
                Thread.Sleep(59);
                File.AppendAllText(LogFile, DateTime.Now.ToLongTimeString() + ": " + se.Message + Environment.NewLine);
            }


        }

        
        private void ResponseStatus(HttpApplication app, int iResponseSubStatus, string sResponseDescription)
        {
            Logging("Set ResponseStatus: " + pwdmustchangeretcode + "." + iResponseSubStatus);
            app.Response.StatusCode = pwdmustchangeretcode;
            app.Response.SubStatusCode = iResponseSubStatus;
            // write to browser
            app.Response.Write("Status Code " + pwdmustchangeretcode + "." + iResponseSubStatus + ": " + sResponseDescription);
            app.CompleteRequest();
        }


        private void AccessDenied(HttpApplication app)
        {
            //TEST
            app.Response.StatusCode = 401;
            app.Response.StatusDescription = "Access Denied";

            // write to browser
            app.Response.Write("401 Access Denied");
            app.CompleteRequest();
        }

        #endregion
    }
}