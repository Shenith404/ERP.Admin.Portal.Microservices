using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Authentication.DataService.Migrations
{
    /// <inheritdoc />
    public partial class _2faenabled : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "TwoFactorAuthenticationCode",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "TwoFactorAuthenticationCodeExpTime",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "TwoFactorAuthenticationCode",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "TwoFactorAuthenticationCodeExpTime",
                table: "AspNetUsers");
        }
    }
}
