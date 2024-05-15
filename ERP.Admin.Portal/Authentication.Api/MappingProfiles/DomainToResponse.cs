using Authentication.Core.DTOs.Response;
using AutoMapper;
using ERP.Authentication.Core.Entity;

namespace Authentication.Api.MappingProfiles
{
    public class DomainToResponse :Profile
    {
        public DomainToResponse()
        {
            CreateMap<UserModel, UserModelResponseDTO>()
           .ForMember(dest => dest.Id,opt => opt.MapFrom(src=>src.Id))
           .ForMember(dest => dest.AddedDate, opt => opt.MapFrom(src => src.AddedDate))
           .ForMember(dest => dest.UpdateDate, opt => opt.MapFrom(src => src.UpdateDate))
           .ForMember(dest => dest.UserName, opt => opt.MapFrom(src => src.UserName))
           .ForMember(dest => dest.NormalizedUserName, opt => opt.MapFrom(src => src.NormalizedUserName))
           .ForMember(dest => dest.Email, opt => opt.MapFrom(src => src.Email))
           .ForMember(dest => dest.NormalizedEmail, opt => opt.MapFrom(src => src.NormalizedEmail))
           .ForMember(dest => dest.EmailConfirmed, opt => opt.MapFrom(src => src.EmailConfirmed))
           .ForMember(dest => dest.TwoFactorEnabled, opt => opt.MapFrom(src => src.TwoFactorEnabled))
           .ForMember(dest => dest.LockoutEnd, opt => opt.MapFrom(src => src.LockoutEnd))
           .ForMember(dest => dest.LockoutEnabled, opt => opt.MapFrom(src => src.LockoutEnabled))
           .ForMember(dest => dest.AccessFailedCount, opt => opt.MapFrom(src => src.AccessFailedCount));





        }
    }
}
