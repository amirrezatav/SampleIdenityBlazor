using System.Security.Claims;

namespace AppIE.Server.Models
{
    public class ApplicationAuthorizeFilterModel
    {
        public string Permission { get; set; }
        public string Roles { get; set; }
        public string Users { get; set; }
        public Claim Claim { get; set; }
    }
}
