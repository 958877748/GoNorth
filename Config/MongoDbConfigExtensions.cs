using Microsoft.Extensions.Configuration;
using GoNorth.Config;

namespace GoNorth.Config
{
    /// <summary>
    /// MongoDB配置扩展方法
    /// </summary>
    public static class MongoDbConfigExtensions
    {
        /// <summary>
        /// 从配置中获取MongoDB配置
        /// </summary>
        /// <param name="configuration">配置</param>
        /// <returns>MongoDB配置</returns>
        public static ConfigurationData GetMongoDbConfig(this IConfiguration configuration)
        {
            var config = new ConfigurationData
            {
                MongoDbConnectionString = configuration.GetValue<string>("MONGO_DB_CONNECTION_STRING") ?? configuration["MongoDb:ConnectionString"],
                MongoDbDbName = configuration.GetValue<string>("MONGO_DB_DB_NAME") ?? configuration["MongoDb:DbName"]
            };
            return config;
        }
    }
}
