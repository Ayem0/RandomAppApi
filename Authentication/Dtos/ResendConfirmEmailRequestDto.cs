using System.ComponentModel.DataAnnotations;

namespace RandomAppApi.Authentication.Dtos;
public class ResendConfirmEmailRequestDto
{
    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Email is invalid.")]
    public required string Email { get; set; }
}