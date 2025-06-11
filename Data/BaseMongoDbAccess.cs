using MongoDB.Driver;
using Microsoft.Extensions.Configuration;
using GoNorth.Config;
using Microsoft.Extensions.Options;

namespace GoNorth.Data
{
    /// <summary>
    /// Base class for mongo Db Access
    /// </summary>
    public class BaseMongoDbAccess
    {
        /// <summary>
        /// MongoDB Client
        /// </summary>
        protected MongoClient _Client;

        /// <summary>
        /// MongoDB Database
        /// </summary>
        protected IMongoDatabase _Database;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="configuration">Configuration</param>
        public BaseMongoDbAccess(IOptions<ConfigurationData> configuration)
        {
            MongoDbConfig dbConfig = configuration.Value.MongoDb;

            _Client = new MongoClient(dbConfig.ConnectionString);
            _Database = _Client.GetDatabase(dbConfig.DbName);
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="configuration">Configuration</param>
        public BaseMongoDbAccess(IConfiguration configuration) : this(configuration.GetMongoDbConfig())
        {
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="configurationData">Configuration Data</param>
        public BaseMongoDbAccess(ConfigurationData configurationData)
        {
            // 优先从环境变量中获取配置
            string connectionString = configurationData.MongoDbConnectionString;
            string dbName = configurationData.MongoDbDbName;
            
            // 如果环境变量中没有配置，则从appsettings中获取
            if (string.IsNullOrEmpty(connectionString))
            {
                connectionString = configurationData.MongoDbConnectionString;
            }
            
            if (string.IsNullOrEmpty(dbName))
            {
                dbName = configurationData.MongoDbDbName;
            }

            _Client = new MongoClient(connectionString);
            _Database = _Client.GetDatabase(dbName);
        }
    }
}
