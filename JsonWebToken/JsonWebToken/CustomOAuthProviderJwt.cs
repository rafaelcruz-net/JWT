using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Linq;

namespace JsonWebToken
{
    internal class CustomOAuthProviderJwt : OAuthAuthorizationServerProvider
    {
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId = string.Empty;
            string clientSecret = string.Empty;
            string symmetricKeyAsBase64 = string.Empty;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }

            if (context.ClientId == null)
            {
                context.SetError("invalid_clientId", "client_Id não pode ser nulo");
                return Task.FromResult<object>(null);
            }

            //Procurando pelo Client Id
            var token = context.ClientId.Split(':');

            var client_id = token.First();
            var accessKey = token.Last();

            var applicationAccess = WebApplicationAccess.Find(client_id);

            if (applicationAccess == null)
            {
                context.SetError("invalid_clientId", "client_Id não encontrado");
                return Task.FromResult<object>(null);
            }

            if (applicationAccess.AccessKey != accessKey)
            {
                context.SetError("invalid_clientId", "access key não encontrado ou inválido");
                return Task.FromResult<object>(null);
            }

            context.Validated();
            return Task.FromResult<object>(null);
        }

        public override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            //FAKE FAZER A VALIDAÇÃO NO BANCO DE DADOS
            if (context.UserName != context.Password)
            {
                context.SetError("invalid_grant", "Usuário ou senha invalidos");
                return Task.FromResult<object>(null);
            }

            var identity = new ClaimsIdentity("JWT");

            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            identity.AddClaim(new Claim("sub", context.UserName));
            identity.AddClaim(new Claim(ClaimTypes.Role, "Administrator")); //PEGAR AS ROLES CORRETAS

            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    {
                         "audience", (context.ClientId == null) ? string.Empty : context.ClientId
                    }
                });

            var ticket = new AuthenticationTicket(identity, props);
            context.Validated(ticket);
            return Task.FromResult<object>(null);
        }

    }
}