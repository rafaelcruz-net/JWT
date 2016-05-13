using Microsoft.Owin.Security.DataHandler.Encoder;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Web;

namespace JsonWebToken
{
    public class WebApplicationAccess
    {
        public String ClientId { get; set; }
        public String AccessKey { get; set; }
        public String SecretKey { get; set; }
        public String ApplicationName { get; set; }

        public static ConcurrentDictionary<string, WebApplicationAccess> WebApplicationAccessList = new ConcurrentDictionary<string, WebApplicationAccess>();
     
        static WebApplicationAccess()
        {

            WebApplicationAccessList.TryAdd("e84a2d13704647d18277966ec839d39e", new WebApplicationAccess()
            {
                AccessKey = "CgP7NyLXtaGmyOgjj3sUMwmAlrSKqa5JyZ4P1OlfQeM",
                SecretKey = "UTboSKRUb13ZmztLtyB0W4BN37ndx_aK8__ry9sxfv8",
                ApplicationName  = "ApplicationTests",
                ClientId = "e84a2d13704647d18277966ec839d39e"
            });
        }
        
        public static WebApplicationAccess GrantApplication(string name)
        {
            var clientId = Guid.NewGuid().ToString("N");

            var key = new byte[32];
            RNGCryptoServiceProvider.Create().GetBytes(key);
            var base64Secret = TextEncodings.Base64Url.Encode(key);


            var accessKey = new byte[32];
            RNGCryptoServiceProvider.Create().GetBytes(key);
            var accessKeyText = TextEncodings.Base64Url.Encode(key);

            WebApplicationAccess newWebApplication = new WebApplicationAccess { ClientId = clientId, SecretKey = base64Secret, AccessKey = accessKeyText, ApplicationName = name };
            WebApplicationAccessList.TryAdd(clientId, newWebApplication);
            return newWebApplication;
        }

        public static WebApplicationAccess Find(string clientId)
        {
            WebApplicationAccess webApplication = null;
            if (WebApplicationAccessList.TryGetValue(clientId, out webApplication))
            {
                return webApplication;
            }

            return null;
        }
    }

}