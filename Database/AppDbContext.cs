using Azure;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using RandomAppApi.Database.models;

namespace RandomAppApi.Database;
public class AppDbContext : IdentityDbContext<User, Role, string>
{
    public AppDbContext(DbContextOptions options) : base(options)
    {
    }

    public DbSet<Conversation> Conversations { get; set; }
    public DbSet<Message> Messages { get; set; }
    public DbSet<UserFriend> UserFriend { get; set; }
    public DbSet<UserBlocked> UserBlocked { get; set; }
    public DbSet<FriendRequest> FriendRequest { get; set; }
    public DbSet<UserConversation> UserConversation { get; set; }

    public DbSet<ConversationRequest> ConversationRequest { get; set; }

    public DbSet<MessageUser> MessageUser { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);


        builder.Entity<UserFriend>()
            .HasKey(e => new { e.UserId, e.FriendUserId });
        // Configurer explicitement la relation pour UserFriend
        builder.Entity<UserFriend>()
            .HasOne(uf => uf.User)
            .WithMany(u => u.Friends)
            .HasForeignKey(uf => uf.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.Entity<UserFriend>()
            .HasOne(uf => uf.FriendUser)
            .WithMany(u => u.FriendsOf)
            .HasForeignKey(uf => uf.FriendUserId)
            .OnDelete(DeleteBehavior.Restrict);
        builder.Entity<UserBlocked>()
    .HasKey(e => new { e.UserId, e.BlockedUserId });
        // Configurer explicitement la relation pour UserBlocked
        builder.Entity<UserBlocked>()
            .HasOne(ub => ub.User)
            .WithMany(u => u.BlockedUsers)
            .HasForeignKey(ub => ub.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.Entity<UserBlocked>()
            .HasOne(ub => ub.BlockedUser)
            .WithMany(u => u.BlockedBy)
            .HasForeignKey(ub => ub.BlockedUserId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.Entity<FriendRequest>()
            .HasOne( f => f.Sender)
            .WithMany( u => u.FriendRequestsSent)
            .HasForeignKey(ub => ub.SenderId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.Entity<FriendRequest>()
            .HasOne(f => f.Receiver)
            .WithMany(u => u.FriendRequestsReceived)
            .HasForeignKey(ub => ub.ReceiverId)
            .OnDelete(DeleteBehavior.Restrict);


        builder.Entity<ConversationRequest>()
            .HasOne(f => f.Receiver)
            .WithMany(u => u.ConversationRequestsReceived)
            .HasForeignKey(ub => ub.ReceiverId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.Entity<ConversationRequest>()
            .HasOne(f => f.Sender)
            .WithMany(u => u.ConversationRequestsSent)
            .HasForeignKey(ub => ub.SenderId)
            .OnDelete(DeleteBehavior.Restrict);


        builder.Entity<ConversationRequest>()
            .HasOne(f => f.Conversation)
            .WithMany( f => f.ConversationRequests)
            .HasForeignKey(ub => ub.ConversationId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.Entity<UserConversation>()
            .HasKey(e => new { e.UserId, e.ConversationId });
        builder.Entity<UserConversation>()
            .HasOne(e => e.User)
            .WithMany(e => e.Conversations)
            .HasForeignKey(e => e.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.Entity<UserConversation>()
            .HasOne(e => e.Conversation)
            .WithMany(e => e.Users)
            .HasForeignKey(e => e.ConversationId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.Entity<Conversation>()
            .HasOne(e => e.Creator)
            .WithMany(e => e.ConversationsCreated)
            .HasForeignKey(e => e.CreatorId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.Entity<Message>()
            .HasOne(f => f.Sender)
            .WithMany(u => u.MessagesSent)
            .HasForeignKey(ub => ub.SenderId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.Entity<MessageUser>()
            .HasKey(e => new { e.MessageId, e.UserId });
        builder.Entity<MessageUser>()
            .HasOne(e => e.User)
            .WithMany(e => e.MessagesReceived)
            .HasForeignKey(e => e.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.Entity<MessageUser>()
            .HasOne(e => e.Message)
            .WithMany(e => e.Users)
            .HasForeignKey(e => e.MessageId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.Entity<Message>()
            .HasOne(e => e.Conversation)
            .WithMany(e => e.Messages)
            .HasForeignKey(e => e.ConversationId)
            .OnDelete(DeleteBehavior.Restrict);










    }
}
