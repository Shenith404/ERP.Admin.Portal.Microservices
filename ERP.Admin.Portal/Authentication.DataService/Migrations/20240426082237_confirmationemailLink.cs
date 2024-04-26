using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Authentication.DataService.Migrations
{
    /// <inheritdoc />
    public partial class confirmationemailLink : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "ConfirmationEmailIssueTime",
                table: "AspNetUsers",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ConfirmationEmailLink",
                table: "AspNetUsers",
                type: "nvarchar(max)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ConfirmationEmailIssueTime",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "ConfirmationEmailLink",
                table: "AspNetUsers");
        }
    }
}
