using Microsoft.AspNetCore.Identity;

namespace RandomAppApi.Database.models;
public class User : IdentityUser
{
    public virtual List<UserFriend> Friends { get; set; } = [];
    public virtual List<UserFriend> FriendsOf { get; set; } = [];

    public virtual List<UserBlocked> BlockedUsers { get; set; } = [];
    public virtual List<UserBlocked> BlockedBy {  get; set; } = [];



    public virtual List<Message> MessagesSent { get; set; } = [];
    public virtual List<MessageUser> MessagesReceived { get; set; } = [];

    public virtual List<FriendRequest> FriendRequestsSent { get; set; } = [];
    public virtual List<FriendRequest> FriendRequestsReceived { get; set; } = [];

    public virtual List<ConversationRequest> ConversationRequestsSent { get; set; } = [];
    public virtual List<ConversationRequest> ConversationRequestsReceived { get; set; } = [];

    public virtual List<UserConversation> Conversations { get; set; } = [];
    public virtual List<Conversation> ConversationsCreated { get; set; } = [];

}