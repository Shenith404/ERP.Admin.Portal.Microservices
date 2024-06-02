using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Authentication.DataService.Migrations
{
    /// <inheritdoc />
    public partial class add_emailto_userdetails : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Email",
                table: "UserDeviceInformations",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Email",
                table: "UserDeviceInformations");
        }
    }
}
