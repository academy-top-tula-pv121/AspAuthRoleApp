using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace AspAuthRoleApp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var roles = new List<Role>
            {
                new Role("admin"),
                new Role("member")
            };

            var users = new List<User>
            {
                new User("bob", "12345", roles[0]),
                new User("joe", "55555", roles[1]),
            };

            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(option =>
                {
                    option.LoginPath = "/login";
                    option.AccessDeniedPath = "/members";
                });
            builder.Services.AddAuthorization();
            var app = builder.Build();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapGet("/login", async (HttpContext context) =>
            {
                context.Response.ContentType = "text/html; charset=utf-8";
                string loginForm = @"<!DOCTYPE html>
<html>
<head>
    <meta charset=""utf-8"" />
    <title>Login page</title>
</head>
<body>
    <h2>Login form</h2>
    <form method=""post"">
        <p>
            <label>Login</label><br />
            <input name=""login"" />
        </p>
        <p>
            <label>Password</label><br />
            <input name=""password"" type=""password"" />
        </p>
        <input type=""submit"" value=""Log In"" />
    </form>
</body>
</html>";
                await context.Response.WriteAsync(loginForm);
            });

            app.MapPost("/login", async (string? redirectUrl, HttpContext context) =>
            {
                var form = context.Request.Form;
                if (!form.ContainsKey("login") || !form.ContainsKey("password"))
                    return Results.BadRequest("Login or password undefined");
                string login = form["login"];
                string password = form["password"];

                User? user = users.FirstOrDefault(u => u.Login == login && u.Password == password);
                if (user is null) return Results.Unauthorized();

                var claims = new List<Claim>
                {
                    new(ClaimsIdentity.DefaultNameClaimType, user.Login),
                    new(ClaimsIdentity.DefaultRoleClaimType, user.Role.Title)
                };

                var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme));
                await context.SignInAsync(principal);
                return Results.Redirect(redirectUrl ?? "/");
            });

            app.Map("/admin", [Authorize(Roles = "admin")] () => "Admin Page");

            app.MapGet("/members", async (HttpContext context) =>
            {
                context.Response.StatusCode = 403;
                await context.Response.WriteAsync("Access Denied");
            });

            app.MapGet("/", [Authorize(Roles = "admin, member")] (HttpContext context) =>
            {
                var login = context.User.FindFirst(ClaimsIdentity.DefaultNameClaimType);
                var role = context.User.FindFirst(ClaimsIdentity.DefaultRoleClaimType);
                return $"Login: {login?.Value}, Role: {role?.Value}";
            });

            app.MapGet("/logout", async (HttpContext context) =>
            {
                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                return "Log out";
            });

            app.Run();
        }
    }
}