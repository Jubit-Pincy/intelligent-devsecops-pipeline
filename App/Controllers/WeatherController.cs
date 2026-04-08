using Microsoft.AspNetCore.Mvc;
using App.Services;

namespace App.Controllers
{
    [ApiController]
    [Route("weather")]
    public class WeatherController : ControllerBase
    {
        private readonly WeatherService _weatherService;

        public WeatherController(WeatherService weatherService)
        {
            _weatherService = weatherService;
        }

        [HttpGet("{city}")]
        public async Task<IActionResult> GetWeather(string city)
        {
            var data = await _weatherService.GetWeatherAsync(city);

            return Ok(data);
        }

        [HttpGet("health")]
        public IActionResult Health()
        {
            return Ok(new { status = "Weather API running" });
        }
    }
}