using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace JsonWebToken.Controllers
{
    public class WebApplicationAccessController : ApiController
    {
        // POST api/<controller>
        public IHttpActionResult Post([FromBody] string applicationName)
        {
            var webApplication = WebApplicationAccess.GrantApplication(applicationName);
            return Ok<WebApplicationAccess>(webApplication);
        }
    }

}