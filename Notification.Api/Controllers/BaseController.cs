using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Notification.DataService.Repository;

namespace Notification.Api.Controllers

{

    [Route("api/[controller]")]
    [ApiController]
    public class BaseController : ControllerBase
    {
        protected readonly IMapper _mapper;
        
        protected readonly IUnitOfWorksNotification _unitOfWorks;

        public BaseController(IMapper mapper, IUnitOfWorksNotification unitOfWorks)
        {
            _mapper = mapper;
            _unitOfWorks = unitOfWorks;
        }
    }
}
