

namespace Notification.DataService.IRepository
{
    public interface IGenericRepository<T> where T : class
    {
        Task<IEnumerable<T>> GetAll(string searchString,Guid receiver);
        Task<T> GetBy(Guid id);
        Task<bool> Add(T entity);

        Task<bool> Updated(T entity);

        Task<bool> Delete(Guid id);
    }
}
