using System.ComponentModel.DataAnnotations;

namespace RandomAppApi.Authentication.Dtos;
public class ConfirmEmailRequestDto
{
    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Email is invalid.")]
    public required string Email { get; set; }

    [Required(ErrorMessage = "Token is required.")]
    public required string Token { get; set; }
}