namespace RandomAppApi.Database.models
{
    public class MessageUser : DefaultFields
    {
        public required string MessageId { get; set; }
        public required string UserId { get; set; }
        public required virtual Message Message { get; set; }
        public required virtual User User { get; set; }
        public bool IsSeen { get; set; } = false;
        public DateTime? SeenAt { get; set; }
    }
}
