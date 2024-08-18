using System.ComponentModel.DataAnnotations;

namespace RandomAppApi.Authentication.Dtos
{
    public class ResetPasswordRequestDto
    {

        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Email is invalid.")]
        public required string Email { get; set; }

        [Required(ErrorMessage = "Token is required.")]
        public required string Token { get; set; }

        [Required(ErrorMessage = "Password is required.")]
        [MinLength(10, ErrorMessage = "Password must be at least 10 characters.")]
        [MaxLength(30, ErrorMessage = "Password must be max 30 characters.")]
        public required string Password { get; set; }

        [Required(ErrorMessage = "Confirm password is required.")]
        [MinLength(10, ErrorMessage = "Confirm password must be at least 10 characters.")]
        [MaxLength(30, ErrorMessage = "Confirm password must be max 30 characters.")]
        [Compare("Password", ErrorMessage = "Passwords do not match.")]
        public required string ConfirmPassword { get; set; }
    }
}
