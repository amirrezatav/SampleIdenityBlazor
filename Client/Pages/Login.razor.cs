using Infrastructure.Model.Requests;
using Radzen;

namespace AppIE.Client.Pages
{
    public partial class Login
    {
        private TokenRequest _tokenModel = new() { Username="09357491027",Password="sS$123456789"};
        private string returnUrl = "/";
        protected void SignUpPage()
        {
            _navigationManager.NavigateTo("/signup");
        }
        protected override async Task OnInitializedAsync()
        {
            var state = await _stateProvider.GetAuthenticationStateAsync();
            if (state.User.Claims.Any())
            {
                _navigationManager.NavigateTo(returnUrl,true);
            }
        }

        private async Task SubmitAsync(LoginArgs args, string name)
        {
            _tokenModel.Username = args.Username;
            _tokenModel.Password = args.Password;
            Console.WriteLine("start");
            var result = await _authenticationManager.Login(_tokenModel);
            if (!result.Succeeded)
            {
                foreach (var message in result.Messages)
                {
                    //_snackBar.Add(message, Severity.Error);
                }
            }
            _navigationManager.NavigateTo(returnUrl, true);
        }

    }
}
