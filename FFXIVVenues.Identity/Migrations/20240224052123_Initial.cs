using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace FFXIVVenues.Identity.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ClientTokens",
                columns: table => new
                {
                    AccessToken = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Scopes = table.Column<string[]>(type: "text[]", nullable: false),
                    UserId = table.Column<long>(type: "bigint", nullable: false),
                    RefreshToken = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    ClientId = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Expiry = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ClientTokens", x => x.AccessToken);
                });

            migrationBuilder.CreateTable(
                name: "DiscordTokens",
                columns: table => new
                {
                    UserId = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    AccessToken = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    RefreshToken = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Expiry = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DiscordTokens", x => x.UserId);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ClientTokens_ClientId",
                table: "ClientTokens",
                column: "ClientId");

            migrationBuilder.CreateIndex(
                name: "IX_ClientTokens_RefreshToken",
                table: "ClientTokens",
                column: "RefreshToken");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ClientTokens");

            migrationBuilder.DropTable(
                name: "DiscordTokens");
        }
    }
}
