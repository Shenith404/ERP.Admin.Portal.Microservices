using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Authentication.DataService.Migrations
{
    /// <inheritdoc />
    public partial class confirmationemailLinkUpdated : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "ConfirmationEmailIssueTime",
                table: "AspNetUsers",
                newName: "ConfirmationEmailLinkExpTime");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "ConfirmationEmailLinkExpTime",
                table: "AspNetUsers",
                newName: "ConfirmationEmailIssueTime");
        }
    }
}
