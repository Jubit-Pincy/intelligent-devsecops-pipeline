using Microsoft.AspNetCore.Mvc;
using App.Services;

namespace App.Controllers
{
    [ApiController]
    [Route("weather")]
    public class WeatherController : ControllerBase
    {
        private readonly IWeatherService _weatherService;

        public WeatherController(IWeatherService weatherService)
        {
            _weatherService = weatherService;
        }

        [HttpGet("{city}")]
        public async Task<IActionResult> GetWeather(string city)
        {
            if (string.IsNullOrWhiteSpace(city) || !Regex.IsMatch(city, @"^[a-zA-Z\s]+$"))
            {
                return BadRequest("Invalid city name.");
            }

            var data = await _weatherService.GetWeatherAsync(city);
            return Ok(data);
        }

        [HttpGet("health")]
        [ProducesResponseType(typeof(object), StatusCodes.Status200OK)]
        public IActionResult Health()
        {
            return Ok(new { status = "Weather API running" });
        }

    }
}