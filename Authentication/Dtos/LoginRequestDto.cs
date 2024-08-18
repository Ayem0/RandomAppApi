using System.ComponentModel.DataAnnotations;

namespace RandomAppApi.Authentication.Dtos;

public class LoginRequestDto 
{
    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Email is invalid.")]
    public required string Email { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    [MinLength(10, ErrorMessage = "Password must be at least 10 characters.")]
    [MaxLength(30, ErrorMessage = "Password must be max 30 characters.")]
    public required string Password { get; set; }
}