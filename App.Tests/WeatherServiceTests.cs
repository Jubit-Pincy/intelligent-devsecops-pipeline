using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Moq;
using Moq.Protected;
using Xunit;
using App.Services;

namespace App.Tests
{
    public class WeatherServiceTests
    {
        [Fact]
        public async Task GetWeatherAsync_ReturnsData_WithoutHittingInternet()
        {
            // 1. Arrange: Mock the HttpMessageHandler (the 'engine' inside HttpClient)
            var handlerMock = new Mock<HttpMessageHandler>(MockBehavior.Strict);
            handlerMock
               .Protected()
               // We mock the 'SendAsync' method which is what HttpClient calls internally
               .Setup<Task<HttpResponseMessage>>(
                  "SendAsync",
                  ItExpr.IsAny<HttpRequestMessage>(),
                  ItExpr.IsAny<CancellationToken>()
               )
               // Return a fake successful response
               .ReturnsAsync(new HttpResponseMessage()
               {
                  StatusCode = HttpStatusCode.OK,
                  Content = new StringContent("Cloudy with a chance of unit tests"),
               })
               .Verifiable();

            // 2. Create an HttpClient that uses our mock handler
            var httpClient = new HttpClient(handlerMock.Object);
            
            // 3. Pass the mocked client into the service
            var service = new WeatherService(httpClient);

            // 4. Act
            var result = await service.GetWeatherAsync("London");

            // 5. Assert
            Assert.Contains("Cloudy", result);
            
            // Verify that the 'network call' was actually attempted exactly once
            handlerMock.Protected().Verify(
               "SendAsync",
               Times.Exactly(1),
               ItExpr.IsAny<HttpRequestMessage>(),
               ItExpr.IsAny<CancellationToken>()
            );
        }
    }
}