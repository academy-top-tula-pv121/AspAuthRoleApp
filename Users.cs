namespace AspAuthRoleApp
{
    class Role
    {
        public string Title { set; get; }
        public Role(string title) => Title = title;
    }

    class User
    {
        public string Login { set; get; }
        public string Password { set; get; }
        public Role Role { set; get; }
        public User(string login, string password, Role role)
        {
            Login = login;
            Password = password;
            Role = role;
        }
    }
}
