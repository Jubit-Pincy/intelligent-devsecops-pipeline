using Xunit;
using App.Services;

namespace App.Tests
{
    public class WeatherServiceTests
    {
        [Fact]
        public async Task GetWeatherAsync_ReturnsStaticData()
        {
            // 1. Arrange: Use the REAL service, not a mock
            var service = new WeatherService();

            // 2. Act
            var result = await service.GetWeatherAsync("AnyCity");

            // 3. Assert: Verify the logic inside the service
            // (Adjust "Sunlight" to match whatever your service actually returns)
            Assert.Contains("Sunlight", result); 
        }
    }
}