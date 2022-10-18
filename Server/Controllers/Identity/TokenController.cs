using Application.Services.IServices;
using Infrastructure.Model.Requests;
using Infrastructure.Services.IServices;
using Microsoft.AspNetCore.Mvc;

namespace AppIE.Server.Controllers.Identity
{

    public class TokenController : ApiBaseController
    {
        private readonly ITokenService _identityService;

        public TokenController(ITokenService identityService, ICurrentUserService currentUserService)
        {
            _identityService = identityService;
        }

        /// <summary>
        /// Get Token (Email, Password)
        /// </summary>
        /// <param name="model"></param>
        /// <returns>Status 200 OK</returns>
        [HttpPost]
        public async Task<ActionResult> Get(TokenRequest model)
        {
            var response = await _identityService.LoginAsync(model);
            return Ok(response);
        }

        /// <summary>
        /// Refresh Token
        /// </summary>
        /// <param name="model"></param>
        /// <returns>Status 200 OK</returns>
        [HttpPost("refresh")]
        public async Task<ActionResult> Refresh([FromBody] RefreshTokenRequest model)
        {
            var response = await _identityService.GetRefreshTokenAsync(model);
            return Ok(response);
        }

        //[ApplicationAuthorize(permission: Permissions.Users.View, roles: RoleConstants.Administrator)]

    }
}