namespace RandomAppApi.Database.models
{
    public class UserBlocked : DefaultFields
    {
        public required string UserId { get; set; }
        public required virtual User User { get; set; }
        public required string BlockedUserId { get; set; }
        public required virtual User BlockedUser { get; set; }
    }
}
