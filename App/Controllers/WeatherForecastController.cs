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
    public class DatabaseHelper
    {
        // Hardcoded credentials - will trigger sonar:S2068
        private string connectionString = "Server=myserver;Database=mydb;User=admin;Password=SuperSecret123!";
        
        public void ExecuteQuery(string userInput)
        {
            // SQL Injection - will trigger sonar:S3649
            string query = "SELECT * FROM users WHERE name = '" + userInput + "'";
            
            // Weak hash - will trigger sonar:S4790
            var md5 = System.Security.Cryptography.MD5.Create();
            byte[] hash = md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(userInput));
        }
    }
}
