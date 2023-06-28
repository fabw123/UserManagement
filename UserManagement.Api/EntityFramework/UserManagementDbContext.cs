using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using UserManagement.Api.Models;

namespace UserManagement.Api.EntityFramework
{
    public class UserManagementDbContext : IdentityDbContext<ApplicationUser>
    {
        public UserManagementDbContext(DbContextOptions<UserManagementDbContext> options): base(options)
        {
                
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder) 
        {
            base.OnModelCreating(modelBuilder);
            SeedIdentityRoles(modelBuilder);
        }

        private void SeedIdentityRoles(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<IdentityRole>().HasData(
                new IdentityRole() { Name ="Admin", ConcurrencyStamp = "1", NormalizedName = "Admin"},
                new IdentityRole() { Name ="User", ConcurrencyStamp = "2", NormalizedName = "User"},
                new IdentityRole() { Name ="Viewer", ConcurrencyStamp = "3", NormalizedName = "Viewer"}
                );
        }
    }
}
