
using AutoMapper;
using Notification.Core.DTOs;
using Notification.Core.Entity;


namespace Notification.Api.Mapping_Profiles
{
    public class DomainToResponse :Profile
    {
        public DomainToResponse()
        {
            CreateMap<NotificationModel, NotificationResponseDTO>()
           .ForMember(dest => dest.Id,opt => opt.MapFrom(src=>src.Id));





        }
    }
}
