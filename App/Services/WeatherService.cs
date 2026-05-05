namespace App.Services
{
    public class WeatherService : IWeatherService
    {
        private readonly HttpClient _httpClient;

        public WeatherService(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        public async Task<string> GetWeatherAsync(string city)
        {
            var url = $"https://wttr.in/{city}?format=j1";

            var response = await _httpClient.GetAsync(url);

            if (!response.IsSuccessStatusCode)
                return "Weather service unavailable";

            return await response.Content.ReadAsStringAsync();
        }
        public string GetCityWeather(string city)
        {
            // BUG: No null check — throws NullReferenceException when city is null
            return "Weather in " + city.ToUpper();
        }
    }
}