using MongoDB.Driver;
using Microsoft.Extensions.Configuration;
using GoNorth.Config;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;

namespace GoNorth.Data
{
    /// <summary>
    /// Base class for mongo Db Access
    /// </summary>
    public class BaseMongoDbAccess
    {
        /// <summary>
        /// Logger
        /// </summary>
        private readonly ILogger _logger;

        /// <summary>
        /// MongoDB Client
        /// </summary>
        protected MongoClient _Client;

        /// <summary>
        /// MongoDB Database
        /// </summary>
        protected IMongoDatabase _Database;

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
                var mongoUrl = new MongoUrl(connectionString);
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
        /// Constructor
        /// </summary>
        /// <param name="configuration">Configuration</param>
        public BaseMongoDbAccess(IOptions<ConfigurationData> configuration, ILogger<BaseMongoDbAccess> logger = null)
        {
            _logger = logger;
            MongoDbConfig dbConfig = configuration.Value.MongoDb;

            _logger?.LogInformation($"使用配置文件中的MongoDB连接配置。连接字符串: {MaskSensitiveInfo(dbConfig.ConnectionString)}, 数据库名: {dbConfig.DbName}");

            _Client = new MongoClient(dbConfig.ConnectionString);
            _Database = _Client.GetDatabase(dbConfig.DbName);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="configuration">Configuration</param>
        public BaseMongoDbAccess(IConfiguration configuration, ILogger<BaseMongoDbAccess> logger = null)
        {
            _logger = logger;
            
            // 优先从环境变量中获取配置
            string connectionString = configuration.GetValue<string>("MONGO_DB_CONNECTION_STRING");
            string dbName = configuration.GetValue<string>("MONGO_DB_DB_NAME");
            string configSource = "环境变量";
            
            // 如果环境变量中没有配置，则从appsettings中获取
            if (string.IsNullOrEmpty(connectionString))
            {
                connectionString = configuration["MongoDb:ConnectionString"];
                configSource = "配置文件(appsettings.json)";
            }
            
            if (string.IsNullOrEmpty(dbName))
            {
                dbName = configuration["MongoDb:DbName"];
            }

            _logger?.LogInformation($"使用{configSource}中的MongoDB连接配置。连接字符串: {MaskSensitiveInfo(connectionString)}, 数据库名: {dbName}");

            _Client = new MongoClient(connectionString);
            _Database = _Client.GetDatabase(dbName);
        }
    }
}
