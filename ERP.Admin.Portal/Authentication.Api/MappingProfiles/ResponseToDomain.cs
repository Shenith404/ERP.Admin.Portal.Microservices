using Authentication.Core.DTOs.Request;
using Authentication.Core.DTOs.Response;
using AutoMapper;
using ERP.Authentication.Core.Entity;

namespace Authentication.Api.MappingProfiles
{
    public class ResponseToDomain : Profile
    {
        public ResponseToDomain()
        {
            CreateMap<UpdateUserRequest, UserModel > ()
           .ForMember(dest => dest.Id,opt => opt.MapFrom(src=>src.Id))
           .ForMember(dest => dest.Email, opt => opt.MapFrom(src => src.Email))
           .ForMember(dest => dest.EmailConfirmed, opt => opt.MapFrom(src => src.EmailConfirmed))
           .ForMember(dest => dest.TwoFactorEnabled, opt => opt.MapFrom(src => src.TwoFactorEnabled))
           .ForMember(dest => dest.LockoutEnd, opt => opt.MapFrom(src => src.LockoutEnd))
           .ForMember(dest => dest.LockoutEnabled, opt => opt.MapFrom(src => src.LockoutEnabled))
           .ForMember(dest => dest.AccessFailedCount, opt => opt.MapFrom(src => src.AccessFailedCount));

        }
    }
}
