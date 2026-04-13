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
        [Fact]
        public void Health_ReturnsOkResult()
        {
            // Arrange
            var mockService = new Moq.Mock<IWeatherService>();
            var controller = new WeatherController(mockService.Object);
        
            // Act
            var result = controller.Health();
        
            // Assert
            var okResult = Assert.IsType<Microsoft.AspNetCore.Mvc.OkObjectResult>(result);
            Assert.NotNull(okResult.Value);
        }
        [Fact]
        public async Task GetWeather_ReturnsBadRequest_WhenCityIsInvalid()
        {
            // Arrange
            var mockService = new Mock<IWeatherService>();
            var controller = new WeatherController(mockService.Object);
            string invalidCity = "London123"; // Contains numbers, should fail regex
        
            // Act
            var result = await controller.GetWeather(invalidCity);
        
            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal("Invalid city name.", badRequestResult.Value);
        }
        
        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [InlineData("   ")]
        public async Task GetWeather_ReturnsBadRequest_WhenCityIsMissing(string city)
        {
            // Arrange
            var mockService = new Mock<IWeatherService>();
            var controller = new WeatherController(mockService.Object);
        
            // Act
            var result = await controller.GetWeather(city);
        
            // Assert
            Assert.IsType<BadRequestObjectResult>(result);
        }
    }
}