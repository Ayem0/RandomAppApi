namespace RandomAppApi.Database.models
{
    public class FriendRequest : DefaultFields
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();

        public required string SenderId { get; set; }
        public required virtual User Sender { get; set; }

        public required string ReceiverId { get; set; }
        public required virtual User Receiver { get; set; }

        public bool IsAccepted { get; set; } = false;
        public DateTime? AcceptedAt { get; set; } 

        public bool IsDeclined { get; set; } = false;
        public DateTime? DeclinedAt { get; set; }

    }
}
