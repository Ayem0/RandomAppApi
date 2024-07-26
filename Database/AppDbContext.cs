using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using RandomAppApi.Authentication.Models;
using Microsoft.EntityFrameworkCore;

namespace RandomAppApi.Database;
public class AppDbContext : IdentityDbContext<User, Role, string>
{
    public AppDbContext(DbContextOptions options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
    }
}