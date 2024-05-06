using Authentication.Core.Entity;
using Authentication.DataService.IRepository;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Authentication.DataService.Repository
{
    public class UserDeviceInformationRepository : GenericRepository<UserDeviceInformation>, IUserDeviceInformationRepository
    {
        public UserDeviceInformationRepository(AppDbContext context, ILogger logger) : base(context, logger)
        {
        }

        public override async Task<IEnumerable<UserDeviceInformation>> GetAll()
        {
            try
            {
                return await dbSet.Where(x => x.Status == 1)
                 .AsNoTracking()
                 .ToListAsync();


            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "{Repo} All mothod has generated Error", typeof(RefreshTokenRepository));

                return new List<UserDeviceInformation>();
            }
        }

    }
}
