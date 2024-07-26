using System.ComponentModel.DataAnnotations;

namespace RandomAppApi.Authentication.Dtos;
public class RegisterRequestDto
{
    [Required(ErrorMessage = "Username is required.")]
    [MinLength(3, ErrorMessage = "Username must be at least 3 characters.")]
    [MaxLength(20, ErrorMessage = "Username must be max 20 characters.")]
    public required string Username { get; set; }

    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Email is invalid.")]
    public required string Email { get; set; }

    [Required(ErrorMessage = "Password is required.")]
    [MinLength(10, ErrorMessage = "Password must be at least 10 characters.")]
    [MaxLength(30, ErrorMessage = "Password must be max 30 characters.")]
    public required string Password { get; set; }

    [Required(ErrorMessage = "Confirm password is required.")]
    [MinLength(10, ErrorMessage = "Confirm password must be at least 10 characters.")]
    [MaxLength(30, ErrorMessage = "Confirm password must be max 30 characters.")]
    [Compare("Password", ErrorMessage = "Passwords do not match.")]
    public required string ConfirmPassword { get; set; }

    public int Elo = 400;
}