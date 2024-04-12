using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Notification.DataService.IRepository;

namespace Notification.DataService.Repository
{
    public class GenericRepository<T> : IGenericRepository<T> where T : class
    {
        public readonly ILogger _logger;
        protected PgsqlDbContext _context;
        internal DbSet<T> dbSet;

        public GenericRepository(ILogger logger, PgsqlDbContext context)
        {
            _logger = logger;
            _context = context;
            dbSet = context.Set<T>();
        }

        public virtual async Task<bool> Add(T entity)
        {
            await dbSet.AddAsync(entity);
            return true;
            
        }

        public  Task<bool> Delete(Guid id)
        {
            throw new NotImplementedException();
        }

        public virtual async Task<IEnumerable<T>> GetAll(string searchString, Guid receiver)
        {
            return await dbSet.ToListAsync();
        }

        public virtual async Task<T> GetBy(Guid id)
        {
            return await dbSet.FindAsync(id);
        }

        public Task<bool> Updated(T entity)
        {
            throw new NotImplementedException();
        }
    }
}
