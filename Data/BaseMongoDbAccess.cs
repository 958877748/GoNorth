using MongoDB.Driver;
using MongoDB.Bson;
using Microsoft.Extensions.Logging;

namespace GoNorth.Data
{
    /// <summary>
    /// Base class for mongo Db Access
    /// </summary>
    /// <summary>
    /// Base class for mongo Db Access
    /// </summary>
    public class BaseMongoDbAccess
    {
        /// <summary>
        /// MongoDB Client
        /// </summary>
        protected IMongoClient _Client;

        /// <summary>
        /// MongoDB Database
        /// </summary>
        protected IMongoDatabase _Database;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="clientFactory">MongoDB客户端工厂</param>
        public BaseMongoDbAccess(IMongoDbClientFactory clientFactory)
        {
            _Client = clientFactory.CreateClient();
            _Database = _Client.GetDatabase(clientFactory.GetDatabaseName());
        }
    }
}
