using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using AppIE.Server.Models;
using Infrastructure.Constant;

namespace AppIE.Server.Filters
{
    public class ApplicationAuthorizeFilter : IAuthorizationFilter
    {
        ApplicationAuthorizeFilterModel _applicationAuthorizeFilter;
        public ApplicationAuthorizeFilter(ApplicationAuthorizeFilterModel applicationAuthorizeFilter)
        {
            _applicationAuthorizeFilter = applicationAuthorizeFilter;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            if (!string.IsNullOrEmpty(_applicationAuthorizeFilter.Roles))
            {
                string[] Roles;
                if (_applicationAuthorizeFilter.Roles.Contains(","))
                    Roles = _applicationAuthorizeFilter.Roles.Split(',');
                else
                    Roles = new string[] { _applicationAuthorizeFilter.Roles };
                foreach (var item in Roles)
                {
                    var hasClaim = context.HttpContext.User.IsInRole(item);
                    if (hasClaim)
                        return;
                }
            }

            if (!string.IsNullOrEmpty(_applicationAuthorizeFilter.Permission))
            {
                var hasClaim = context.HttpContext.User.Claims.Any(c => c.Type == ApplicationClaimTypes.Permission && c.Value == _applicationAuthorizeFilter.Permission);
                if (hasClaim)
                    return;
            }

            if (_applicationAuthorizeFilter.Claim != null)
            {
                var hasClaim = context.HttpContext.User.Claims.Any(c => c.Type == _applicationAuthorizeFilter.Claim.Type && c.Value == _applicationAuthorizeFilter.Claim.Value);
                if (hasClaim)
                    return;
            }

            if (!string.IsNullOrEmpty(_applicationAuthorizeFilter.Users))
            {
                string[] Users;
                if (_applicationAuthorizeFilter.Users.Contains(","))
                    Users = _applicationAuthorizeFilter.Users.Split(',');
                else
                    Users = new string[] { _applicationAuthorizeFilter.Users };
                foreach (var item in Users)
                {
                    var hasClaim = context.HttpContext.User.IsInRole(item);
                    if (hasClaim)
                        return;
                }
            }

            context.Result = new ForbidResult();

        }
    }

}
