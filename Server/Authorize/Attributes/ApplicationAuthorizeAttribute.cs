using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using AppIE.Server.Filters;
using AppIE.Server.Models;

namespace AppIE.Server.Attributes
{
    public class ApplicationAuthorizeAttribute : TypeFilterAttribute
    {
        public ApplicationAuthorizeAttribute(string permission = "", string roles = "", string users = "", string claimType = "", string claimValue = "") : base(typeof(ApplicationAuthorizeFilter))
        {
            Arguments = new object[] { new ApplicationAuthorizeFilterModel() {
            Claim = new Claim(claimType, claimValue),
            Permission = permission,
            Roles = roles,
            Users = users
            } };
        }
    }
}
