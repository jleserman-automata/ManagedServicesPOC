using Automata;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

Host.CreateDefaultBuilder(args)
    .UseWindowsService(options => { options.ServiceName = "Interactive Launcher Service"; })
    .ConfigureLogging(logging =>
    {
        logging.ClearProviders();
        logging.AddEventLog(cfg =>
        {
            cfg.SourceName = "InteractiveLauncher";
            cfg.LogName = "Application"; // or create a custom log
        });
        logging.AddSimpleConsole(); // optional for debugging when run console
    })
    .ConfigureServices(services =>
    {
        //LogManager.Initialize("C:\\ProgramData\\Automata\\Logs", "InteractiveLauncher");
        services.AddHostedService<InteractiveLaunchWorker>();
    })
    .Build()
    .Run();
