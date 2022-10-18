using Application.Configurations;
using Microsoft.EntityFrameworkCore;
using Infrastructure.Contexts;

namespace AppIE.Extensions
{
    internal static class WebApplicationExtensions
    {
        private static AppConfiguration GetApplicationSettings(IConfiguration configuration)
        {
            var applicationSettingsConfiguration = configuration.GetSection(nameof(AppConfiguration));
            return applicationSettingsConfiguration.Get<AppConfiguration>();
        }
        internal static IApplicationBuilder UseExceptionHandling(this WebApplication app)
        {
            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            return app;
        }
        internal static IApplicationBuilder UseForwarding(this WebApplication app, IConfiguration configuration)
        {
            AppConfiguration config = GetApplicationSettings(configuration);
            if (config.BehindSSLProxy)
            {
                app.UseCors();
                app.UseForwardedHeaders();
            }

            return app;
        }
        internal static IApplicationBuilder UseEndpoints(this IApplicationBuilder app)
            => app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
                endpoints.MapControllers();
                endpoints.MapFallbackToFile("index.html");
            });
        internal static void ConfigureSwagger(this IApplicationBuilder app)
        {
            app.UseSwagger();
            app.UseSwaggerUI(options =>
            {
                options.SwaggerEndpoint("/swagger/v1/swagger.json", typeof(Program).Assembly.GetName().Name);
                options.RoutePrefix = "swagger";
                options.DisplayRequestDuration();
            });
        }
        internal static IApplicationBuilder InitializeDatabase(this WebApplication app)
        {
            using var serviceScope = app.Services.CreateScope();
            var context = serviceScope.ServiceProvider.GetService<IApplicationContext>();
            if (context.Database.IsSqlServer())
                context.Database.Migrate();
            var initializers = serviceScope.ServiceProvider.GetServices<IDatabaseSeeder>();
            foreach (var initializer in initializers)
            {
                initializer.Initialize();
            }
            return app;
        }
    }
}