
namespace RandomAppApi.Database.models
{
    public class UserConversation : DefaultFields
    {
        public required string UserId { get; set; }
        public required string ConversationId { get; set; }
        public required virtual User User { get; set; }
        public required virtual Conversation Conversation { get; set; }


    }
}
