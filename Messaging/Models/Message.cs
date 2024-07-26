namespace RandomAppApi.Messaging.Models;

class Message
{
    public Guid Id { get; set; }
    public Guid SenderId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? ModifiedAt { get; set; }
    public bool? IsModified { get; set; }
    public required string Content { get; set; }
}