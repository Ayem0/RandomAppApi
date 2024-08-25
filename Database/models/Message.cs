namespace RandomAppApi.Database.models
{
    public class Message : DefaultFields
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string? SenderId { get; set; }
        public required string ConversationId { get; set; }
        public required string Content { get; set; }


        public required virtual Conversation Conversation { get; set; }
        public virtual User? Sender { get; set; }

        public virtual List<MessageUser> Users { get; set; } = [];
    }
}