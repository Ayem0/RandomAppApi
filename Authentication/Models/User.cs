using Microsoft.AspNetCore.Identity;

namespace RandomAppApi.Authentication.Models;
public class User : IdentityUser
{
    public int Elo { get; set; }

}