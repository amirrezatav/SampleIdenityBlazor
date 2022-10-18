
using AppIE;

var builder = WebApplication.CreateBuilder(args);
builder.ConfigureServices(builder.Configuration)
    .ConfigurePipeline(builder.Configuration)
    .Run();