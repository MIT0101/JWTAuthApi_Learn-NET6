using JWTAuthApi_Learn.Models;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using JWTAuthApi_Learn.Data;
using System.Security.Cryptography;

namespace JWTAuthApi_Learn.Auth
{
    public class JwtAuthnticationManager
    {
        private readonly string key;

        private readonly Dictionary<string, string> tempUsers=new Dictionary<string, string>() {
            {"mog","moh123" },
            {"vod","vod123"}
        };

        public JwtAuthnticationManager(string key)
        {
            this.key = key;
        }


        //must send password sened by user and get his salt and his hashedpassword 
        private bool isUserPasswordHashValid(string passwordRecevied, byte[] passwordHash, byte[] passwordSalt) {

            using (HMACSHA512 hmac512=new HMACSHA512(passwordSalt)) { 
                byte[] hashOfReceviedPassword = hmac512.ComputeHash(System.Text.Encoding.UTF8.GetBytes(passwordRecevied));
                return hashOfReceviedPassword.SequenceEqual(passwordHash);
            }
        
        }

        //genrate passwordHash And Salte
        private void genratePasswordHashAndSalt(string password,out byte[] passwordHash,out byte[] passwordSalt) {
            using (HMACSHA512 hmac512=new HMACSHA512()) {
                passwordSalt = hmac512.Key;
                passwordHash = hmac512.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        public string authinticateUser(UserDto user,List<Claim> claims) {

            bool found = tempUsers.Any(u => u.Key==user.username&&u.Value==user.password);
            if (!found) {
                return null;
            }
                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                
                var tokenKey=Encoding.ASCII.GetBytes(key);

                SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor {
                    Subject = new ClaimsIdentity(claims),
                    Expires = DateTime.Now.AddDays(2),
                    SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(tokenKey)
                    ,SecurityAlgorithms.HmacSha256Signature),


                
                };

                var token=tokenHandler.CreateToken(tokenDescriptor);

                return tokenHandler.WriteToken(token);
           
        }
    }
}
