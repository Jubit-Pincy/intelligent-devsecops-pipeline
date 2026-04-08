namespace App.Services
{
    public class WeatherService
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
    }
}