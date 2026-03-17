using Microsoft.AspNetCore.Mvc;
using SecureApp.Models;

namespace SecureApp.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        [HttpGet("health")]
        public IActionResult HealthCheck()
        {
            return Ok(new { status = "Application is running" });
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            return Ok(new
            {
                message = "Login endpoint hit",
                user = request.Username
            });
        }
    }
}
