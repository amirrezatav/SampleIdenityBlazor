using AppIE.Server;
using Application.Configurations;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.FileProviders;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;
using AppIE.Extensions;

namespace AppIE
{
    public static class HostingExtensions
    {
        public static WebApplication ConfigureServices(this WebApplicationBuilder builder, IConfiguration configuration)
        {
            var services = builder.Services;
            // services.AddForwarding(configuration);
            services.AddAppConfiguration(configuration);
            services.AddRazorPages();
            services.AddCurrentUserService();
            services.AddDatabase(configuration);
            services.AddInfrastructure(configuration);
            services.AddJwtAuthentication(services.GetApplicationSettings(configuration));
            services.AddSignalR();
           // services.RegisterSwagger();
            services.AddApiVersioning(config =>
            {
                config.DefaultApiVersion = new ApiVersion(1, 0);
                config.AssumeDefaultVersionWhenUnspecified = true;
                config.ReportApiVersions = true;
            });
            services.AddCors(opt =>
            {
                opt.AddPolicy(name: "DefualCors", builder =>
                {
                    builder.WithOrigins("https://localhost:5003/", "https://localhost:5003", "https://localhost:5004")
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            });

            return builder.Build();
        }
        public static WebApplication ConfigurePipeline(this WebApplication app, IConfiguration _configuration)
        {
           //  app.UseForwarding(_configuration);
            app.UseExceptionHandling();
            app.UseHttpsRedirection();
            app.UseBlazorFrameworkFiles();
            app.UseStaticFiles();
            //app.UseStaticFiles(new StaticFileOptions
            //{
            //    FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), @"Files")),
            //    RequestPath = new PathString("/Files")
            //});
            app.UseRouting();
            app.UseCors("DefualCors");
            app.UseAuthentication();
            app.UseAuthorization();
            //app.ConfigureSwagger();
            app.UseEndpoints();
            app.InitializeDatabase();
            return app;
        }
    }
}
