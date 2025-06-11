using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;
using MongoDB.Bson;

namespace GoNorth.Data
{
    public interface IMongoDbClientFactory
    {
        IMongoClient CreateClient();
        string GetDatabaseName();
    }

    public class MongoDbClientFactory : IMongoDbClientFactory
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<MongoDbClientFactory> _logger;
        private string _connectionString;
        private string _databaseName;

        public MongoDbClientFactory(IConfiguration configuration, ILogger<MongoDbClientFactory> logger)
        {
            _configuration = configuration;
            _logger = logger;
            Initialize();
        }

        private void Initialize()
        {
            _logger.LogInformation("正在初始化MongoDB客户端工厂...");
            
            // 优先从环境变量获取配置
            _connectionString = _configuration.GetValue<string>("MONGO_DB_CONNECTION_STRING");
            _databaseName = _configuration.GetValue<string>("MONGO_DB_DB_NAME");
            
            _logger.LogInformation("环境变量配置 - 连接字符串: {IsSet}", 
                string.IsNullOrEmpty(_connectionString) ? "未设置" : "已设置");
            _logger.LogInformation("环境变量配置 - 数据库名称: {IsSet}", 
                string.IsNullOrEmpty(_databaseName) ? "未设置" : "已设置");

            // 如果环境变量未设置，则从配置文件获取
            if (string.IsNullOrEmpty(_connectionString))
            {
                _connectionString = _configuration["MongoDb:ConnectionString"];
                _logger.LogInformation("使用appsettings.json中的连接字符串配置");
            }
            
            if (string.IsNullOrEmpty(_databaseName))
            {
                _databaseName = _configuration["MongoDb:DbName"];
                _logger.LogInformation("使用appsettings.json中的数据库名称配置");
            }

            // 记录最终使用的配置（脱敏处理）
            var maskedConnectionString = MaskSensitiveInfo(_connectionString);
            _logger.LogInformation("MongoDB连接参数 - 连接字符串: {ConnectionString}", 
                string.IsNullOrEmpty(maskedConnectionString) ? "未设置" : maskedConnectionString);
            _logger.LogInformation("MongoDB连接参数 - 数据库名称: {DbName}", 
                _databaseName ?? "未设置");
        }

        public IMongoClient CreateClient()
        {
            try
            {
                _logger.LogInformation("正在创建MongoDB客户端...");
                var client = new MongoClient(_connectionString);
                
                // 测试连接
                _logger.LogInformation("MongoDB客户端创建成功，正在测试连接...");
                var database = client.GetDatabase(_databaseName);
                var isMongoLive = database.RunCommandAsync((Command<BsonDocument>)"{ping:1}").Wait(1000);
                _logger.LogInformation("MongoDB连接测试: {Status}", 
                    isMongoLive ? "成功" : "超时");
                    
                return client;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "MongoDB客户端创建失败");
                throw;
            }
        }

        public string GetDatabaseName() => _databaseName;

        private string MaskSensitiveInfo(string connectionString)
        {
            if (string.IsNullOrEmpty(connectionString))
                return string.Empty;
                
            try
            {
                var mongoUrl = new MongoUrl(connectionString);
                if (string.IsNullOrEmpty(mongoUrl.Username))
                    return connectionString;
                    
                return connectionString.Replace(
                    $"{mongoUrl.Username}:{mongoUrl.Password}@", 
                    $"{mongoUrl.Username}:***@"
                );
            }
            catch
            {
                return connectionString;
            }
        }
    }
}
