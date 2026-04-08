using Microsoft.AspNetCore.Mvc;
using Xunit;
using App.Controllers; // This links to your main application's code

namespace App.Tests 
{
    public class WeatherForecastControllerTests
    {
        [Fact]
        public void HealthCheck_ReturnsOkResult()
        {
            // 1. Arrange: Instantiate the actual controller from your main app
            var controller = new WeatherForecastController();

            // 2. Act: Call the HealthCheck endpoint
            var result = controller.HealthCheck();

            // 3. Assert: Verify the endpoint did what it was supposed to do
            // It should return an HTTP 200 OK
            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Equal(200, okResult.StatusCode);
            
            // It should return an object containing our status message
            Assert.NotNull(okResult.Value);
        }
        
        [Fact]
        public void Login_ReturnsOkResult_WithUsername()
        {
            // Arrange
            var controller = new WeatherForecastController();
            var request = new App.Models.LoginRequest { Username = "TestUser", Password = "TestPassword" };

            // Act
            var result = controller.Login(request);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Equal(200, okResult.StatusCode);
            Assert.NotNull(okResult.Value);
        }
    }
}