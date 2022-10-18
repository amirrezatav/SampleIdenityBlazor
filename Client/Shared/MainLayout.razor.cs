using AppIE.Client.Managers;
using Infrastructure.Constant;
using Microsoft.AspNetCore.Components;
using Radzen;

namespace AppIE.Client.Shared
{
    public partial class MainLayout
    {
        [Inject]
        public DialogService DialogService { get; set; }
        protected async Task Logout()
        {

            var res = await DialogService.Confirm("آیا مطئن هستید میخواهید خارج شوید؟", "خروج از حساب", new ConfirmOptions() { OkButtonText = "بله", CancelButtonText = "خیر" });
            if (res.HasValue && res.Value)
            {
                var _authenticationStateProvider = new ApplicationStateProvider(null, null);
                await _localStorage.RemoveItemAsync(StorageConstants.Local.AuthToken);
                await _localStorage.RemoveItemAsync(StorageConstants.Local.RefreshToken);
                await _localStorage.RemoveItemAsync(StorageConstants.Local.UserImageURL);
                _authenticationStateProvider.MarkUserAsLoggedOut();
                _httpClient.DefaultRequestHeaders.Authorization = null;
                await OnParametersSetAsync();
                res = await DialogService.Confirm("شما خارج شدید.", "خروج از حساب", new ConfirmOptions() { OkButtonText = "باشه", CancelButtonText = "ورود مجدد" });
                if (res.HasValue && !res.Value)
                {
                    _navigationManager.NavigateTo("/login");
                }
            }
        }
    }
}
