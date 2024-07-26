using System.ComponentModel.DataAnnotations;

namespace RandomAppApi.Authentication.Dtos;

public class RefreshRequestDto
{
    [Required(ErrorMessage = "Refresh token is required.")]
    public string? RefreshToken { get; set; }
}