namespace RandomAppApi.Database.models
{
    public class Conversation : DefaultFields 
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string? CreatorId { get; set; }
        public string? Name { get; set; }



        public virtual List<Message> Messages { get; set; } = [];
        public virtual List<UserConversation> Users { get; set; } = [];
        public virtual User? Creator { get; set; }
        public virtual List<ConversationRequest> ConversationRequests { get; set; } = [];


    }
}