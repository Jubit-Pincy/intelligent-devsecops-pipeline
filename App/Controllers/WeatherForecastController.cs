using Microsoft.AspNetCore.Mvc;
using App.Models;

namespace App.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
    [HttpGet("health")]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)] 
    public IActionResult HealthCheck()
    {
        return Ok(new { status = "Application is running" });
    }
    
    [HttpPost("login")]
    [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
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
