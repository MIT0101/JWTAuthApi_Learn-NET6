using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using JWTAuthApi_Learn.Auth;
using Microsoft.AspNetCore.Authorization;
using JWTAuthApi_Learn.Models;
using System.Security.Claims;
using JWTAuthApi_Learn.Data;

namespace JWTAuthApi_Learn.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private JwtAuthnticationManager _jwtAuthnticationManager;
        public AuthController(JwtAuthnticationManager jwtAuthnticationManager)
        {
            this._jwtAuthnticationManager = jwtAuthnticationManager;
        }

        //test user auth
        [HttpGet("TestUser")]
 
        public async Task<ActionResult<string>> testAuth() {

            var userName = User.FindFirstValue(ClaimTypes.Name);
            var userRole = User.FindFirstValue(ClaimTypes.Role);
           
            return Ok(userName+" "+userRole);
        }

        [HttpPost("logIn")]
        [AllowAnonymous]
        public async Task<ActionResult<string>> Login([FromBody] UserDto user) {
            string userToken = _jwtAuthnticationManager.authinticateUser(user, genratNormalUserClames(user,"User"));
            if (string.IsNullOrEmpty(userToken))
            {
                return Unauthorized();
            }

            return userToken;
        }

        //for genrate normalUser Clames

        private List<Claim> genratNormalUserClames(UserDto user,string role) {


            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name,user.username),
                new Claim(ClaimTypes.Role,role)

            };

            return claims;
        
        }


        //test method
        [AllowAnonymous]
        [HttpGet("testAll")]
        public async Task< ActionResult<string>> testAll() { 
        return Ok("Welcome EvryBodey");
        }
    }
}
