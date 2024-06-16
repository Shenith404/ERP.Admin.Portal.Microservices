using Authentication.Core.DTOs.Request;
using Authentication.Core.DTOs.Response;
using Authentication.DataService.IConfiguration;
using Authentication.jwt;
using AutoMapper;
using ERP.Authentication.Core.Entity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Notification.DataService.Repository;

namespace Authentication.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
   // [Authorize(Roles ="Admin")]
    public class AdminController : BaseController
    {
         public AdminController(IJwtTokenHandler jwtTokenHandler, UserManager<UserModel> userManager, IMapper mapper, IUnitOfWorks unitOfWorks)
            : base(jwtTokenHandler, userManager, mapper, unitOfWorks)
        {


        }

        [HttpPost]
        [Route("getUsers-details")]
        //[Authorize] should change
        public async Task<IActionResult> GetUsers([FromBody] string? searchString)
        {
            var users = _userManager.Users.ToList();

            if (users == null || !users.Any())
            {
                return BadRequest("User List is Empty");
            }

            if (string.IsNullOrEmpty(searchString))
            {
                return Ok( _mapper.Map<List<UserModelResponseDTO>>(users));
            }

            var searchResult = users.Where(u =>
                u.UserName!.Contains(searchString, StringComparison.OrdinalIgnoreCase) || // Search by username
                u.Email!.Contains(searchString, StringComparison.OrdinalIgnoreCase)   // Search by email
                  ).ToList();

            //map the result
            var mapResutls = _mapper.Map<List<UserModelResponseDTO>>(searchResult);

            return Ok(mapResutls);
        }


        [HttpGet]
        [Route("Delete-User")]
        //[Authorize] should change
        public async Task<IActionResult> DeleteUser([FromBody] string email)
        {

            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(email);

                //check user is exist or not
                if (user == null)
                {
                    return BadRequest("User is not exist");

                }
                var result = await _userManager.DeleteAsync(user);
                if (result.Succeeded)
                {
                    return Ok("User is Deleted");

                }
                return BadRequest("Can't Delete User");


            }
            return BadRequest("Invalid email");
        }





        [HttpPost]
        [Route("Assign-Role")]
        public async Task<IActionResult> AssignRoles([FromBody] AssignRoleRequestDTO assignRoleRequestDTO) {
            if (ModelState.IsValid) {
                try
                {

                    UserModel? user = await _userManager.FindByEmailAsync(assignRoleRequestDTO.UserEmail);
                    if (user != null) {

                        //we only allow to have one role
                        //therefore  we remove all roles before assign a role
                        var roles = await _userManager.GetRolesAsync(user);
                        

                        var result = await _userManager.AddToRoleAsync(user, assignRoleRequestDTO.Role);

                        if (result.Succeeded) {
                            await _userManager.RemoveFromRoleAsync(user, roles[0]);
                            return Ok($"{assignRoleRequestDTO.Role} is assigned to {assignRoleRequestDTO.UserEmail}");
                        }
                        return BadRequest(result.Errors);
                    }
                    return BadRequest("Email is Does not exist");
                }
                catch (Exception ex)
                {
                    return BadRequest("Error :" + ex.ToString());
                }
            }

            return BadRequest("Model is Not valid");
        }

         [HttpPost]
        [Route("get-Roles")]
        public async Task<IActionResult> GetUserRoles([FromBody] string userId) {
            if (ModelState.IsValid) {
                try
                {

                    UserModel? user = await _userManager.FindByIdAsync(userId);
                    if (user != null) {

                        //we only allow to have one role
                        //therefore  we remove all roles before assign a role
                        var roles = await _userManager.GetRolesAsync(user);
                       



                            return Ok(roles[0]);
                        
                       
                    }
                    return BadRequest("User is Does not exist");
                }
                catch (Exception ex)
                {
                    return BadRequest("Error :" + ex.ToString());
                }
            }

            return BadRequest("Model is Not valid");
        }

        [HttpPost]
        [Route("Lock-User")]
        public async Task<IActionResult> LockUser([FromBody] LockOutDetailsInfoRequestDTO lockOutDetailsInfoRequestDTO)
        {
            if (ModelState.IsValid) {

                try
                {
                    UserModel? user = await _userManager.FindByEmailAsync(lockOutDetailsInfoRequestDTO.Email);
                    if (user != null) {

                        //Unlock the User
                        if (lockOutDetailsInfoRequestDTO.LockUser == false) {
                            user.LockoutEnd = null;
                            var isUnlocked = await _userManager.UpdateAsync(user);
                            if (isUnlocked.Succeeded) {
                                return Ok($"user {lockOutDetailsInfoRequestDTO.Email} is Unlocked");
                            }
                            return BadRequest(isUnlocked.Errors);

                        }


                        // Lockout Enable
                        var lockOutEnableResult = await _userManager.SetLockoutEnabledAsync(user, lockOutDetailsInfoRequestDTO.LockoutEnable);
                        if (!lockOutEnableResult.Succeeded) {

                            return BadRequest(lockOutEnableResult.Errors);
                        }

                        // Lock User
                        user.LockoutEnd = lockOutDetailsInfoRequestDTO.LockoutEndDate;
                        var lockUserResult = await _userManager.UpdateAsync(user);

                        if (lockUserResult.Succeeded) {
                            return Ok("Save changes Successful");
                        }

                    }

                    return BadRequest("Invalid User");
                }
                catch (Exception ex)
                {
                    return BadRequest(ex.ToString());
                }
            }
            return BadRequest("Model is Not Valid");
        }

        [HttpPost]
        [Route("locked-status")]
        public async Task<IActionResult> UserLockedStatus([FromBody] string id)
        {
            if (ModelState.IsValid)
            {
                var user = await  _userManager.FindByIdAsync(id);
                if (user != null) {
                    var status = await _userManager.IsLockedOutAsync(user);

                    return Ok(status);
                }
            }
            return BadRequest();
        }

        [HttpPost]
        [Route("login-details")]
        public async Task<IActionResult> GetUserLoginDetails([FromBody] string searchString)
        {

            if (ModelState.IsValid)
            {
                var details = await _unitOfWorks.UserDeviceInformations.GetAll();


                if (details == null || !details.Any())
                {
                    return BadRequest("User List is Empty");
                }

                if (string.IsNullOrEmpty(searchString))
                {
                    return Ok(_mapper.Map<IEnumerable<UserLoginDeviceInfoResponse>>(details));
                }

                var searchResult = details.Where(u =>
                    u.IP!.Contains(searchString, StringComparison.OrdinalIgnoreCase) || // Search by username
                    u.UserAgentDetails!.Contains(searchString, StringComparison.OrdinalIgnoreCase) ||
                     u.Email!.Contains(searchString, StringComparison.OrdinalIgnoreCase)// Search by email
                      ).ToList();

   

                var mapped= _mapper.Map<IEnumerable<UserLoginDeviceInfoResponse>>(searchResult);
                    
                return Ok(mapped);
            }

            return BadRequest("Model is not Valid");
        }

      }

    

}
