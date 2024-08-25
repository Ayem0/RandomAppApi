namespace RandomAppApi.Database.models
{
    public class DefaultFields
    {
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? ModifiedAt { get; set; }
        public DateTime? DeletedAt { get; set; }
        public bool IsModified { get; set; } = false;
        public bool IsDeleted { get; set; } = false;
        public bool IsAdmin { get; set; } = false;
    }
}
