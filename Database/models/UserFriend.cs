namespace RandomAppApi.Database.models
{
    public class UserFriend : DefaultFields
    {
        public required string UserId { get; set; }
        public required virtual User User { get; set; }
        public required string FriendUserId { get; set; }
        public required virtual User FriendUser { get; set; }

    }
}
