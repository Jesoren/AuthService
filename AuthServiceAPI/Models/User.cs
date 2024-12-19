namespace AuthService.Models;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

public class User
{
    [BsonId]
    [BsonRepresentationAttribute(BsonType.ObjectId)]
    public ObjectId id { get; set; }
    public string? Username { get; set; }
    public string? Password { get; set; }
    public string? Email { get; set; }
    public DateTime Birthday { get; set; }
    public string Role { get; set; }
}