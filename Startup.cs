using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections;
using System.Globalization;
using System.Collections.Generic;
using GoNorth.Data;
using GoNorth.Services.Email;
using GoNorth.Services.Encryption;
using GoNorth.Data.User;
using GoNorth.Data.Role;
using GoNorth.Authentication;
using GoNorth.Config;
using GoNorth.Localization;
using System;
using System.Globalization;
using System.Collections.Generic;
using GoNorth.Data.Timeline;
using GoNorth.Services.Timeline;
using Microsoft.AspNetCore.Http;
using GoNorth.Data.Project;
using GoNorth.Data.Kortisto;
using GoNorth.Data.LockService;
using Microsoft.AspNetCore.HttpOverrides;
using GoNorth.Data.Kirja;
using GoNorth.Services.Kirja;
using GoNorth.Data.Karta;
using GoNorth.Services.Karta;
using GoNorth.Data.Tale;
using GoNorth.Data.Styr;
using GoNorth.Data.Aika;
using GoNorth.Data.TaskManagement;
using GoNorth.Services.TaskManagement;
using GoNorth.Services.ImplementationStatusCompare;
using Microsoft.AspNetCore.Localization;
using GoNorth.Services.User;
using GoNorth.Data.Evne;
using GoNorth.Services.FlexFieldThumbnail;
using GoNorth.Data.Exporting;
using GoNorth.Services.Export.Placeholder;
using GoNorth.Services.Export.LanguageKeyGeneration;
using GoNorth.Services.Export.Dialog;
using GoNorth.Services.Export.Data;
using GoNorth.Services.Security;
using Microsoft.AspNetCore.Mvc;
using System.Reflection;
using System.IO;
using GoNorth.Data.ProjectConfig;
using GoNorth.Services.ProjectConfig;
using GoNorth.Services.Export.NodeGraphExport;
using GoNorth.Services.Export.TemplateParsing;
using GoNorth.Services.Export.ExportSnippets;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;
using GoNorth.Services.DataMigration;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Threading.Tasks;
using System.Text.Json.Serialization;
using GoNorth.Services.Export.Placeholder.LegacyRenderingEngine;
using GoNorth.Services.Export.Placeholder.ScribanRenderingEngine.LanguageKeyGenerator;
using GoNorth.Services.Export.Dialog.ActionRendering.Localization;
using GoNorth.Services.Export.Dialog.ConditionRendering.Localization;
using GoNorth.Services.Export.DailyRoutine;
using GoNorth.Services.CsvHandling;
using GoNorth.Services.Project;
using GoNorth.Services.ReferenceAnalyzer;
using GoNorth.Services.TimerJob;
using GoNorth.Services.TimerJob.JobDefinitions;
using GoNorth.Data.StateMachines;
using GoNorth.Services.Export.StateMachines;
using Microsoft.AspNetCore.Hosting;
using MongoDB.Driver;
using MongoDB.Driver.Core.Configuration;

namespace GoNorth
{
    /// <summary>
    /// Startup Class
    /// </summary>
    public class Startup
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="configuration">Configuration for the application</param>
        public Startup(IConfiguration configuration, IWebHostEnvironment env)
        {
            // 创建新的配置构建器
            var configBuilder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddEnvironmentVariables();
            
            // 构建配置
            var config = configBuilder.Build();
            
            // 读取环境变量
            var mongoDbConnectionString = Environment.GetEnvironmentVariable("MONGO_DB_CONNECTION_STRING");
            var mongoDbName = Environment.GetEnvironmentVariable("MONGO_DB_DB_NAME");
            
            // 如果环境变量中有配置，则更新配置
            if (!string.IsNullOrEmpty(mongoDbConnectionString) || !string.IsNullOrEmpty(mongoDbName))
            {
                var configValues = new Dictionary<string, string>();
                
                if (!string.IsNullOrEmpty(mongoDbConnectionString))
                {
                    configValues["MongoDb:ConnectionString"] = mongoDbConnectionString;
                    Console.WriteLine($"在 Startup 构造函数中设置 MongoDB 连接字符串: {MaskSensitiveInfo(mongoDbConnectionString)}");
                }
                if (!string.IsNullOrEmpty(mongoDbName))
                {
                    configValues["MongoDb:DbName"] = mongoDbName;
                    Console.WriteLine($"在 Startup 构造函数中设置数据库名: {mongoDbName}");
                }
                
                // 使用内存配置提供程序添加配置
                configBuilder.AddInMemoryCollection(configValues);
            }
            
            // 构建最终配置
            Configuration = configBuilder.Build();
            
            // 记录最终配置
            Console.WriteLine($"最终配置 - MongoDB 连接字符串: {MaskSensitiveInfo(Configuration["MongoDb:ConnectionString"])}");
            Console.WriteLine($"最终配置 - 数据库名: {Configuration["MongoDb:DbName"]}");
        }

        /// <summary>
        /// 隐藏敏感信息（如密码）
        /// </summary>
        /// <param name="connectionString">连接字符串</param>
        /// <returns>隐藏敏感信息后的连接字符串</returns>
        private string MaskSensitiveInfo(string connectionString)
        {
            if (string.IsNullOrEmpty(connectionString))
                return string.Empty;

            try
            {
                var mongoUrl = new MongoDB.Driver.MongoUrl(connectionString);
                if (string.IsNullOrEmpty(mongoUrl.Password))
                    return connectionString;

                // 隐藏密码
                return connectionString.Replace($":{mongoUrl.Password}@", ":***@");
            }
            catch
            {
                // 如果解析失败，返回原始字符串
                return connectionString;
            }
        }

        /// <summary>
        /// Configuration
        /// </summary>
        public IConfiguration Configuration { get; }

        /// <summary>
        /// This method gets called by the runtime. Use this method to add services to the container.
        /// </summary>
        /// <param name="services">Services</param>
        public void ConfigureServices(IServiceCollection services)
        {
            // 配置 MongoDB 选项
            services.Configure<MongoDbConfig>(Configuration.GetSection("MongoDb"));
            
            // 获取配置并记录
            var mongoConfig = new MongoDbConfig();
            Configuration.GetSection("MongoDb").Bind(mongoConfig);
            
            Console.WriteLine($"配置加载 - MongoDB 连接字符串: {MaskSensitiveInfo(mongoConfig.ConnectionString)}");
            Console.WriteLine($"配置加载 - 数据库名: {mongoConfig.DbName}");
            
            // 显式注册 MongoDbConfig 为单例，确保所有服务使用相同的配置
            services.AddSingleton(mongoConfig);
            
            // 显式注册 MongoClient 和 IMongoDatabase
            services.AddSingleton<IMongoClient>(sp => {
                var connectionString = mongoConfig.ConnectionString;
                Console.WriteLine($"创建 MongoClient，连接字符串: {MaskSensitiveInfo(connectionString)}");
                return new MongoClient(connectionString);
            });
            
            services.AddScoped<IMongoDatabase>(sp => {
                var client = sp.GetRequiredService<IMongoClient>();
                var dbName = mongoConfig.DbName;
                Console.WriteLine($"获取数据库: {dbName}");
                return client.GetDatabase(dbName);
            });
            
            // 获取配置数据
            ConfigurationData configData = Configuration.Get<ConfigurationData>();
            
            // 记录最终使用的配置
            Console.WriteLine($"最终使用的 MongoDB 连接字符串: {MaskSensitiveInfo(configData.MongoDb.ConnectionString)}");
            Console.WriteLine($"最终使用的数据库名: {configData.MongoDb.DbName}");
            
            // Add Identity
            services.AddIdentity<GoNorthUser, GoNorthRole>(options => {
                // Password settings
                options.Password.RequireDigit = true;
                options.Password.RequiredLength = Constants.MinPasswordLength;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = false;

                // Lockout settings
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
                options.Lockout.MaxFailedAccessAttempts = 10;

                // User settings
                options.User.RequireUniqueEmail = true;
            }).AddUserManager<GoNorthUserManager>().AddRoleManager<GoNorthRoleManager>().
               AddUserStore<GoNorthUserStore>().AddRoleStore<GoNorthRoleStore>().AddErrorDescriber<GoNorthIdentityErrorDescriber>().
               AddUserValidator<GoNorthUserValidator>().AddDefaultTokenProviders();
            
            
            // Ensure that the correct status is returned for api calls
            services.ConfigureApplicationCookie(o =>
            {
                o.Events = new CookieAuthenticationEvents()
                {
                    OnRedirectToLogin = (ctx) =>
                    {
                        if (ctx.Request.Path.StartsWithSegments("/api") && ctx.Response.StatusCode == 200)
                        {
                            ctx.Response.StatusCode = 401;
                        }
                        else
                        {
                            ctx.Response.Redirect(ctx.RedirectUri);
                        }
                        return Task.CompletedTask;
                    },
                    OnRedirectToAccessDenied = (ctx) =>
                    {
                        if (ctx.Request.Path.StartsWithSegments("/api") && ctx.Response.StatusCode == 200)
                        {
                            ctx.Response.StatusCode = 403;
                        }
                        else
                        {
                            ctx.Response.Redirect(ctx.RedirectUri);
                        }
                        return Task.CompletedTask;
                    }
                };
            });

            if(configData.Misc.UseGdpr)
            {
                services.Configure<CookiePolicyOptions>(options =>
                {
                    options.CheckConsentNeeded = context => true;
                    options.MinimumSameSitePolicy = SameSiteMode.None;
                });

                services.Configure<CookieTempDataProviderOptions>(options => {
                    options.Cookie.IsEssential = true;
                });
            }

            // Framework services
            services.AddHttpContextAccessor();

            // Application services
            services.AddTransient<IConfigViewAccess, AppSettingsConfigViewAccess>();

            services.AddTransient<IProjectConfigProvider, ProjectConfigProvider>();

            services.AddTransient<IUserProjectAccess, UserProjectAccess>();

            services.AddTransient<IEmailSender, EmailSender>();
            services.AddTransient<IEncryptionService, AesEncryptionService>();
            services.AddTransient<ISecureTokenGenerator, RngSecureTokenGenerator>();
            services.AddTransient<IXssChecker, XssChecker>();
            services.AddTransient<ITimelineService, TimelineService>();
            services.AddTransient<ITimelineTemplateService, HtmlTimelineTemplateService>();

            services.AddTransient<IKortistoNpcImageAccess, KortistoFileSystemNpcImageAccess>();

            services.AddTransient<IStyrItemImageAccess, StyrFileSystemItemImageAccess>();

            services.AddTransient<IEvneSkillImageAccess, EvneFileSystemSkillImageAccess>();

            services.AddTransient<IKirjaPageParserService, KirjaPageParserService>();
            services.AddTransient<IKirjaFileAccess, KirjaFileSystemAccess>();

            services.AddTransient<IKartaImageProcessor, ImageSharpKartaImageProcessor>();
            services.AddTransient<IKartaImageAccess, KartaFileSystemImageAccess>();
            services.AddTransient<IKartaMarkerLabelSync, KartaMarkerLabelSync>();

            services.AddTransient<ITaskImageAccess, TaskImageFileSystemAccess>();
            services.AddTransient<ITaskImageParser, TaskImageParser>();
            services.AddTransient<ITaskNumberFill, TaskNumberFill>();
            services.AddTransient<ITaskTypeDefaultProvider, TaskTypeDefaultProvider>();

            services.AddTransient<IKortistoThumbnailService, ImageSharpKortistoThumbnailService>();
            services.AddTransient<IEvneThumbnailService, ImageSharpEvneThumbnailService>();
            services.AddTransient<IStyrThumbnailService, ImageSharpStyrThumbnailService>();

            services.AddTransient<IImplementationStatusComparer, GenericImplementationStatusComparer>();

            services.AddTransient<IUserCreator, UserCreator>();
            services.AddTransient<IUserDeleter, UserDeleter>();

            services.AddTransient<IExportTemplatePlaceholderResolver, ExportTemplatePlaceholderResolver>();
            services.AddTransient<IExportDialogParser, ExportDialogParser>();
            services.AddTransient<IExportDialogFunctionGenerator, ExportDialogFunctionGenerator>();
            services.AddTransient<IExportDialogRenderer, ExportDialogRenderer>();
            services.AddScoped<ILanguageKeyGenerator, LanguageKeyGenerator>();
            services.AddScoped<ILanguageKeyReferenceCollector, LanguageKeyReferenceCollector>();
            services.AddTransient<IScribanLanguageKeyGenerator, ScribanLanguageKeyGenerator>();
            services.AddScoped<IExportDialogFunctionNameGenerator, ExportDialogFunctionNameGenerator>();
            services.AddScoped<IDailyRoutineFunctionNameGenerator, DailyRoutineFunctionNameGenerator>();
            services.AddScoped<IStateMachineFunctionNameGenerator, StateMachineFunctionNameGenerator>();
            services.AddTransient<IConditionRenderer, ConditionRenderer>();
            services.AddTransient<ILegacyDailyRoutineEventPlaceholderResolver, LegacyDailyRoutineEventPlaceholderResolver>();
            services.AddTransient<ILegacyDailyRoutineEventContentPlaceholderResolver, LegacyDailyRoutineEventContentPlaceholderResolver>();
            services.AddTransient<IDailyRoutineNodeGraphFunctionGenerator, DailyRoutineNodeGraphFunctionGenerator>();
            services.AddTransient<IStateMachineNodeGraphFunctionGenerator, StateMachineNodeGraphFunctionGenerator>();
            services.AddTransient<IDailyRoutineFunctionRenderer, DailyRoutineFunctionRenderer>();
            services.AddTransient<IStateMachineFunctionRenderer, StateMachineFunctionRenderer>();
            services.AddScoped<IExportCachedDbAccess, ExportCachedDbAccess>();
            services.AddTransient<INodeGraphExporter, NodeGraphExporter>();
            services.AddTransient<INodeGraphParser, NodeGraphParser>();
            services.AddTransient<IExportSnippetParser, ExportSnippetParser>();
            services.AddTransient<IScribanExportSnippetParser, ScribanExportSnippetParser>();
            services.AddTransient<IScribanIncludeTemplateRefParser, ScribanIncludeTemplateRefParser>();
            services.AddTransient<IExportTemplateParser, ExportTemplateParser>();
            services.AddTransient<IExportSnippetFunctionNameGenerator, ExportSnippetFunctionNameGenerator>();
            services.AddTransient<IExportSnippetNodeGraphFunctionGenerator, ExportSnippetNodeGraphFunctionGenerator>();
            services.AddTransient<IExportSnippetRelatedObjectUpdater, ExportSnippetRelatedObjectUpdater>();
            services.AddTransient<IExportSnippetFunctionRenderer, ExportSnippetFunctionRenderer>();
            services.AddTransient<IExportSnippetRelatedObjectNameResolver, ExportSnippetRelatedObjectNameResolver>();
            services.AddScoped<IActionTranslator, ActionTranslator>();
            services.AddScoped<IConditionTranslator, ConditionTranslator>();

            services.AddScoped<GoNorthUserManager>();

            services.AddScoped<IUserClaimsPrincipalFactory<GoNorthUser>, GoNorthUserClaimsPrincipalFactory>();

            services.AddTransient<ICsvGenerator, CsvGenerator>();
            services.AddTransient<ICsvParser, CsvParser>();

            services.AddTransient<IReferenceAnalyzer, ReferenceAnalyzer>();

            services.AddTransient<ILockCleanupTimerJob, LockCleanupTimerJob>();
            services.AddSingleton<ITimerJobManager, TimerJobManager>();
            
            // Database
            services.AddTransient<ILockServiceDbAccess, LockServiceMongoDbAccess>();
            services.AddScoped<IUserDbAccess, UserMongoDbAccess>();
            services.AddScoped<IUserPreferencesDbAccess, UserPreferencesMongoDbAccess>();
            services.AddScoped<IRoleDbAccess, RoleMongoDbAccess>();
            services.AddScoped<ITimelineDbAccess, TimelineMongoDbAccess>();
            services.AddScoped<IProjectDbAccess, ProjectMongoDbAccess>();

            services.AddScoped<IProjectConfigDbAccess, ProjectConfigMongoDbAccess>();

            services.AddScoped<IKortistoFolderDbAccess, KortistoFolderMongoDbAccess>();
            services.AddScoped<IKortistoNpcTemplateDbAccess, KortistoNpcTemplateMongoDbAccess>();
            services.AddScoped<IKortistoNpcDbAccess, KortistoNpcMongoDbAccess>();
            services.AddScoped<IKortistoNpcTagDbAccess, KortistoNpcTagMongoDbAccess>();
            services.AddScoped<IKortistoNpcImplementationSnapshotDbAccess, KortistoNpcImplementationSnapshotMongoDbAccess>();
            services.AddScoped<IKortistoImportFieldValuesLogDbAccess, KortistoImportFieldValuesLogMongoDbAccess>();

            services.AddScoped<IStyrFolderDbAccess, StyrFolderMongoDbAccess>();
            services.AddScoped<IStyrItemTemplateDbAccess, StyrItemTemplateMongoDbAccess>();
            services.AddScoped<IStyrItemDbAccess, StyrItemMongoDbAccess>();
            services.AddScoped<IStyrItemTagDbAccess, StyrItemTagMongoDbAccess>(); 
            services.AddScoped<IStyrItemImplementationSnapshotDbAccess, StyrItemImplementationSnapshotMongoDbAccess>();
            services.AddScoped<IStyrImportFieldValuesLogDbAccess, StyrImportFieldValuesLogMongoDbAccess>();

            services.AddScoped<IEvneFolderDbAccess, EvneFolderMongoDbAccess>();
            services.AddScoped<IEvneSkillTemplateDbAccess, EvneSkillTemplateMongoDbAccess>();
            services.AddScoped<IEvneSkillDbAccess, EvneSkillMongoDbAccess>();
            services.AddScoped<IEvneSkillTagDbAccess, EvneSkillTagMongoDbAccess>();
            services.AddScoped<IEvneSkillImplementationSnapshotDbAccess, EvneSkillImplementationSnapshotMongoDbAccess>();
            services.AddScoped<IEvneImportFieldValuesLogDbAccess, EvneImportFieldValuesLogMongoDbAccess>();
            
            services.AddScoped<IKirjaPageDbAccess, KirjaPageMongoDbAccess>();
            services.AddScoped<IKirjaPageVersionDbAccess, KirjaPageVersionMongoDbAccess>();
            services.AddScoped<IKirjaPageReviewDbAccess, KirjaPageReviewMongoDbAccess>();

            services.AddScoped<IKartaMapDbAccess, KartaMapMongoDbAccess>();
            services.AddScoped<IKartaMarkerImplementationSnapshotDbAccess, KartaMarkerImplementationSnapshotMongoDbAccess>();

            services.AddScoped<ITaleDbAccess, TaleMongoDbAccess>();
            services.AddScoped<ITaleDialogImplementationSnapshotDbAccess, TaleDialogImplementationSnapshotMongoDbAccess>();

            services.AddScoped<IStateMachineDbAccess, StateMachineMongoDbAccess>();
            services.AddScoped<IStateMachineImplementationSnapshotDbAccess, StateMachineImplementationSnapshotMongoDbAccess>();

            services.AddScoped<IAikaChapterOverviewDbAccess, AikaChapterOverviewMongoDbAccess>();
            services.AddScoped<IAikaChapterDetailDbAccess, AikaChapterDetailMongoDbAccess>();
            services.AddScoped<IAikaQuestDbAccess, AikaQuestMongoDbAccess>();
            services.AddScoped<IAikaQuestImplementationSnapshotDbAccess, AikaQuestImplementationSnapshotMongoDbAccess>();

            services.AddScoped<IExportTemplateDbAccess, ExportTemplateMongoDbAccess>();
            services.AddScoped<IIncludeExportTemplateDbAccess, IncludeExportTemplateMongoDbAccess>();
            services.AddScoped<IExportDefaultTemplateProvider, ExportDefaultTemplateProvider>();
            services.AddScoped<ICachedExportDefaultTemplateProvider, CachedExportDefaultTemplateProvider>();
            services.AddScoped<IExportSettingsDbAccess, ExportSettingsMongoDbAccess>();
            services.AddScoped<IDialogFunctionGenerationConditionDbAccess, DialogFunctionGenerationConditionMongoDbAccess>();
            services.AddScoped<IDialogFunctionGenerationConditionProvider, DialogFunctionGenerationConditionProvider>();
            services.AddScoped<IExportFunctionIdDbAccess, ExportFunctionIdMongoDbAccess>();
            services.AddScoped<IObjectExportSnippetDbAccess, ObjectExportSnippetMongoDbAccess>();
            services.AddScoped<IObjectExportSnippetSnapshotDbAccess, ObjectExportSnippetSnapshotMongoDbAccess>();

            services.AddScoped<ILanguageKeyDbAccess, LanguageKeyMongoDbAccess>();

            services.AddScoped<ITaskBoardDbAccess, TaskBoardMongoDbAccess>();
            services.AddScoped<ITaskTypeDbAccess, TaskTypeMongoDbAccess>();
            services.AddScoped<ITaskGroupTypeDbAccess, TaskGroupTypeMongoDbAccess>();
            services.AddScoped<ITaskBoardCategoryDbAccess, TaskBoardCategoryMongoDbAccess>();
            services.AddScoped<ITaskNumberDbAccess, TaskNumberMongoDbAccess>();
            services.AddScoped<IUserTaskBoardHistoryDbAccess, UserTaskBoardHistoryMongoDbAccess>();

            services.AddScoped<IDbSetup, MongoDbSetup>();

            // Localization
            CultureInfo defaultCulture = new CultureInfo("en");
            List<CultureInfo> supportedCultures = new List<CultureInfo>
            {
                new CultureInfo("de"),
                new CultureInfo("en")
            };
            services.AddJsonLocalization(options => {
                options.FallbackCulture = defaultCulture;
                options.ResourcesPath = "Resources";
            });

            services.Configure<RequestLocalizationOptions>(options =>
            {
                options.DefaultRequestCulture = new RequestCulture(defaultCulture, defaultCulture);
                options.SupportedCultures = supportedCultures;
                options.SupportedUICultures = supportedCultures;
            });

            services.AddMvcCore().AddViewLocalization().AddMvcLocalization().AddApiExplorer().AddAuthorization().AddRazorPages().AddJsonOptions(jsonOptions => {
                jsonOptions.JsonSerializerOptions.PropertyNameCaseInsensitive = true;
                jsonOptions.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
            });

            // Configuration
            services.Configure<ConfigurationData>(Configuration);

            // Register the Swagger generator
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo 
                    { 
                        Title = "GoNorth API", 
                        Version = "v1",
                        Description = "A portal to build storys for RPGs and other open world games.",
                        Contact = new OpenApiContact
                        {
                            Name = "Steffen Werhahn, former Nörtershäuser"
                        },
                        License = new OpenApiLicense
                        {
                            Name = "Use under MIT",
                            Url = new Uri("https://github.com/steffendx/GoNorth/blob/master/LICENSE")
                        }
                    });

                string baseDirectory = AppDomain.CurrentDomain.BaseDirectory;
                string commentsFileName = Assembly.GetExecutingAssembly().GetName().Name + ".XML";
                string commentsFile = Path.Combine(baseDirectory, commentsFileName);
                c.IncludeXmlComments(commentsFile);
            });

            services.AddHostedService<AutoDataMigrator>();
        }

        /// <summary>
        /// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        /// </summary>
        /// <param name="app">Application builder</param>
        /// <param name="env">Hosting environment</param>
        /// <param name="timerJobManager">Timer Job Manager</param>
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ITimerJobManager timerJobManager)
        {
            // 记录所有环境变量
            Console.WriteLine("===== 环境变量开始 =====");
            var envVars = Environment.GetEnvironmentVariables();
            foreach (DictionaryEntry envVar in envVars)
            {
                // 过滤掉敏感信息
                string value = envVar.Key.ToString().ToUpper().Contains("PASSWORD") || 
                              envVar.Key.ToString().ToUpper().Contains("SECRET") ||
                              envVar.Key.ToString().ToUpper().Contains("KEY") ||
                              envVar.Key.ToString().ToUpper().Contains("CONNECTION")
                    ? "[REDACTED]" 
                    : envVar.Value?.ToString();
                    
                Console.WriteLine($"{envVar.Key} = {value}");
            }
            Console.WriteLine("===== 环境变量结束 =====");
            
            // 显式检查MongoDB相关环境变量
            Console.WriteLine("\n===== MongoDB 配置 =====");
            Console.WriteLine($"MONGO_DB_CONNECTION_STRING 存在: {!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("MONGO_DB_CONNECTION_STRING"))}");
            Console.WriteLine($"MONGO_DB_DB_NAME 存在: {!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("MONGO_DB_DB_NAME"))}");
            Console.WriteLine("========================\n");

            ConfigurationData configData = Configuration.Get<ConfigurationData>();
            
            if (env.IsDevelopment())
            {
                EnvironmentSettings.IsDevelopment = true;
                app.UseDeveloperExceptionPage();
            }
            else
            {
                EnvironmentSettings.IsDevelopment = false;
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseForwardedHeaders(new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
            });

            app.UseRequestLocalization();

            app.UseStaticFiles();

            if(configData.Misc.UseGdpr)
            {
                app.UseCookiePolicy();
            }

            app.UseRouting();

            app.UseAuthentication();
            app.Use(async (context, next) =>
            {
                // 如果是登录请求
                if (context.Request.Path.StartsWithSegments("/Account/Login") && context.Request.Method == "POST")
                {
                    // 从请求中获取用户名
                    var form = await context.Request.ReadFormAsync();
                    var username = form["Email"].ToString();
                    
                    // 检查用户是否已存在
                    var userDbAccess = context.RequestServices.GetRequiredService<IUserDbAccess>();
                    var user = await userDbAccess.GetUserByEmail(username);
                    
                    if (user == null)
                    {
                        // 创建新用户
                        var newUser = new GoNorthUser
                        {
                            UserName = username,
                            Email = username,
                            NormalizedUserName = username.ToUpper(),
                            NormalizedEmail = username.ToUpper(),
                            EmailConfirmed = true,
                            DisplayName = username,
                            Roles = new List<string> { "User" }
                        };
                        
                        // 使用默认密码 "admin123"
                        var userManager = context.RequestServices.GetRequiredService<UserManager<GoNorthUser>>();
                        var password = "admin123";
                        var result = await userManager.CreateAsync(newUser, password);
                        
                        if (result.Succeeded)
                        {
                            // 创建成功后继续处理登录
                            await next();
                        }
                        else
                        {
                            // 创建失败，返回错误
                            context.Response.StatusCode = 400;
                            await context.Response.WriteAsync("Failed to create user");
                        }
                    }
                    else
                    {
                        // 用户已存在，继续处理登录
                        await next();
                    }
                }
                else
                {
                    await next();
                }
            });
            app.UseAuthorization();

            app.UseEndpoints(endpoints => {
                endpoints.MapDefaultControllerRoute();
                endpoints.MapRazorPages();
            });

            timerJobManager.InitializeTimerJobs();

            if(env.IsDevelopment())
            {
                app.UseSwagger();

                app.UseSwaggerUI(c =>
                {
                    c.SwaggerEndpoint("/swagger/v1/swagger.json", "GoNorth Api");
                });
            }
        }
    }
}
