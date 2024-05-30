using AutoMapper;
using Microsoft.AspNetCore.Mvc;
using Notification.Core.DTOs;
using Notification.Core.Entity;
using Notification.DataService.Repository;

namespace Notification.Api.Controllers
{

    public class NotificationController : BaseController
    {
        public NotificationController(IMapper mapper, IUnitOfWorksNotification unitOfWorks) : base(mapper, unitOfWorks)
        {
        }

        //Get All Notifications
        [HttpPost]
        [Route("All-Notifications")]
        public async Task<IActionResult> GetAllNotifications([FromBody] NotificationRequestDTO requestDTO)
        {
            if (ModelState.IsValid)
            {
                
                var result = await _unitOfWorks.Notifications.GetAll(requestDTO.SearchString, requestDTO.ReceiverId);
                var mapResutls = _mapper.Map<List<NotificationResponseDTO>>(result);
                return Ok(mapResutls);
            }
            return BadRequest("Model is not valid");

        }

        [HttpPost]
        [Route("Create")]
        public async Task<IActionResult> CreateNotification([FromBody] CreateNotificationDTO createNotificationDTO)
        {
            if (ModelState.IsValid)
            {
                var Notification = new NotificationModel
                {
                    Title = createNotificationDTO.Title,
                    Content = createNotificationDTO.Content,
                    ReadStatus = false,
                    ReceiverId = createNotificationDTO.ReceiverId,
                    Priority = createNotificationDTO.Priority,
                    Link = createNotificationDTO.Link,
                    Type = createNotificationDTO.Type,
                    Status = 1
                };
                await _unitOfWorks.Notifications.Add(Notification);
                var result = await _unitOfWorks.CompleteAsync();

                if (result == true)
                {
                    return Ok("Notification Created");
                }
                return BadRequest("Can't Create Notification");



            }
            return BadRequest("Model is not valid");
        }

        [HttpPost]
        [Route("Mark-as-Read")]
        public async Task<IActionResult> MarkNotificationAsRead([FromBody] Guid notificationId)
        {
            if(ModelState.IsValid)
            {
                await _unitOfWorks.Notifications.MarkNotificationAsReadAsync(notificationId);
                var result = await _unitOfWorks.CompleteAsync();
                if(result == true)
                {
                    return Ok("Notification is Marked as read");
                }
                return BadRequest($"Server Error {result}");

            }
            return BadRequest("Input is not valid");
        }



        [HttpPost]
        [Route("MarkAll-as-Read")]
        public async Task<IActionResult> MarkAllNotificationAsRead([FromBody] Guid userId)
        {
            if (ModelState.IsValid)
            {
                await _unitOfWorks.Notifications.MarkAllNotificationAsReadAsync(userId);
               
                var result = await _unitOfWorks.CompleteAsync();
                if (result == true)
                {
                    return Ok("Notification is Marked as read");
                }
                return BadRequest("Server Error");

            }
            return BadRequest("Input is not valid");
        }

    }
}
