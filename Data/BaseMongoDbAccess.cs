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
        public BaseMongoDbAccess(IConfiguration configuration)
        {
            // 优先从环境变量中获取配置
            string connectionString = configuration.GetValue<string>("MONGO_DB_CONNECTION_STRING");
            string dbName = configuration.GetValue<string>("MONGO_DB_DB_NAME");
            
            // 如果环境变量中没有配置，则从appsettings中获取
            if (string.IsNullOrEmpty(connectionString))
            {
                connectionString = configuration["MongoDb:ConnectionString"];
            }
            
            if (string.IsNullOrEmpty(dbName))
            {
                dbName = configuration["MongoDb:DbName"];
            }

            _Client = new MongoClient(connectionString);
            _Database = _Client.GetDatabase(dbName);
        }
    }
}
