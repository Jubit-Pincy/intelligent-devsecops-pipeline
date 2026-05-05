using Microsoft.AspNetCore.Mvc;
using System.Text.RegularExpressions;
using App.Services;

namespace App.Controllers
{
    [ApiController]
    [Route("weather")]
    public class WeatherController : ControllerBase
    {
        private readonly IWeatherService _weatherService;

        // Best Practice: Define a static timeout to avoid magic numbers
        private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

        public WeatherController(IWeatherService weatherService)
        {
            _weatherService = weatherService;
        }

        [HttpGet("{city}")]
        public async Task<IActionResult> GetWeather(string city)
        {
            // Fix: Added RegexOptions and a explicit timeout
            if (string.IsNullOrWhiteSpace(city) || 
                !Regex.IsMatch(city, @"^[a-zA-Z\s]+$", RegexOptions.None, RegexTimeout))
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

        [HttpGet("city")]
        public IActionResult GetByCity([FromQuery] string city)
        {
            var result = _weatherService.GetCityWeather(city);
            return Ok(result);
        }
    }
}