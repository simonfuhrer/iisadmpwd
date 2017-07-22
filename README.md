iisadmpwd
=========

I wrote an HttpModule that inherits from IHttpModule.  IISADMPWD is a ASP.NET Http Module written in managed C# code.  The Module subscribed to the Begin and End Request. It check the password expiration status on the Active Directory. Based on the result it will return e custom status code.   

If you have any issues or feedback, please make sure to post to the Discussion and Issue Tracker sections. - Thanks!

Quick-Install Guide:
1. Install IISADMPWD.dll and Interop.ActiveDs.dll to GAC c:\windows\assembly (gacutil.exe)
2. Edit the web.config. Sample Configuiraton Files ist attached in this solutution
4. Test, Test. Provide Feedback. thx

