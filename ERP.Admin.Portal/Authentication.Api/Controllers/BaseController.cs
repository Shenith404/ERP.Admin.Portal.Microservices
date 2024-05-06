﻿using Authentication.DataService.IConfiguration;
using Authentication.jwt;
using AutoMapper;
using ERP.Authentication.Core.Entity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Notification.DataService.IRepository;
using Notification.DataService.Repository;

namespace Authentication.Api.Controllers
{
    public class BaseController : ControllerBase
    {
        protected readonly IJwtTokenHandler _jwtTokenHandler;
        protected readonly UserManager<UserModel> _userManager;
        protected readonly IMapper _mapper;
        protected readonly IUnitOfWorks _unitOfWorks;
        protected readonly IUnitOfWorksNotification _unitOfWorksNotification;
        

        public BaseController(IJwtTokenHandler jwtTokenHandler, UserManager<UserModel> userManager,
            IMapper mapper,IUnitOfWorks unitOfWorks,
            IUnitOfWorksNotification unitOfWorksNotification)
        {
            _jwtTokenHandler = jwtTokenHandler;
            _userManager = userManager;
            _mapper = mapper;
            _unitOfWorks= unitOfWorks;
             _unitOfWorksNotification = unitOfWorksNotification;
        }

        
    }
}
