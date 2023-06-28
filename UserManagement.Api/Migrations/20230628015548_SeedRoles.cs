using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace UserManagement.Api.Migrations
{
    public partial class SeedRoles : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "9fa47264-21ce-4bfa-a386-dd563f781bfa", "2", "User", "User" });

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "af1a5e11-f1f8-49df-8ad7-9c2a3c77994e", "3", "Viewer", "Viewer" });

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[] { "f8cc9bab-eb85-49e2-9a33-f2881a81e7b5", "1", "Admin", "Admin" });
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "9fa47264-21ce-4bfa-a386-dd563f781bfa");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "af1a5e11-f1f8-49df-8ad7-9c2a3c77994e");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "f8cc9bab-eb85-49e2-9a33-f2881a81e7b5");
        }
    }
}
