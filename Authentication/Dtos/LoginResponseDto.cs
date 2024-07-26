namespace RandomAppApi.Authentication.Dtos;
public class LoginResponseDto
{
    public string? AccessToken { get; set; }

    public string? RefreshToken { get; set; }
}