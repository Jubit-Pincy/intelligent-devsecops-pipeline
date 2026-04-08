using Moq;
using Xunit;
using Microsoft.AspNetCore.Mvc;
using App.Controllers;
using App.Services;

namespace App.Tests
{
    public class WeatherControllerTests
    {
        [Fact]
        public async Task GetWeather_ReturnsOk_WithMockedData()
        {
            // 1. Arrange: Mock the service so we don't hit a real API
            var mockService = new Mock<IWeatherService>();
            mockService.Setup(s => s.GetWeatherAsync(It.IsAny<string>()))
                       .ReturnsAsync("Cloudy with a chance of successful builds");

            var controller = new WeatherController(mockService.Object);

            // 2. Act
            var result = await controller.GetWeather("London");

            // 3. Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Equal("Cloudy with a chance of successful builds", okResult.Value);
        }
    }
}