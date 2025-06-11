using Microsoft.Extensions.Configuration;

namespace GoNorth.Config
{
    public static class MongoDbConfigExtensions
    {
        public static MongoDbConfig GetMongoDbConfig(this IConfiguration configuration)
        {
            var mongoDbConfig = new MongoDbConfig();
            
            // First try to get from environment variables
            var connectionString = configuration.GetValue<string>("MONGO_DB_CONNECTION_STRING");
            var dbName = configuration.GetValue<string>("MONGO_DB_DB_NAME");
            
            // If not found in environment variables, fall back to appsettings
            if (string.IsNullOrEmpty(connectionString))
            {
                connectionString = configuration["MongoDb:ConnectionString"];
            }
            
            if (string.IsNullOrEmpty(dbName))
            {
                dbName = configuration["MongoDb:DbName"];
            }
            
            mongoDbConfig.ConnectionString = connectionString;
            mongoDbConfig.DbName = dbName;
            
            return mongoDbConfig;
        }
    }
}
