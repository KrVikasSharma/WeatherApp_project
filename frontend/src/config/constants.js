// constants.js

// OpenWeather API Configuration
export const WEATHER_API = {
  BASE_URL: "https://api.openweathermap.org/data/2.5",
  GEO_URL: "https://api.openweathermap.org/geo/1.0",
  KEY: "e645059b9beecff4a74e70c12c408e16", // Add your OpenWeather API key here
  ICON_URL: "https://openweathermap.org/img/wn"
};

// Your backend API configuration (for Node/Express/Postgres)
export const LOCAL_API = {
  BASE_URL: "http://localhost:4000",
  AUTH: {
    REGISTER: "/auth/signup",
    LOGIN: "/auth/login",
    PROFILE: "/auth/me"
  }
  // Add more endpoints here as you build more features!
};

// API Endpoints (for weather, if using OpenWeatherMap)
export const ENDPOINTS = {
  WEATHER: "/weather",
  FORECAST: "/forecast",
  AIR_QUALITY: "/air_pollution",
  GEOCODING: "/direct",
  ONECALL: "/onecall"
};

// Default Settings
export const DEFAULTS = {
  UNITS: "metric",
  TEMPERATURE_UNIT: "C",
  SEARCH_HISTORY_LIMIT: 5,
  FORECAST_DAYS: 5
};

// Error Messages
export const ERRORS = {
  LOCATION_NOT_FOUND: "Location not found. Please try another search.",
  GEOLOCATION_NOT_SUPPORTED: "Geolocation is not supported by your browser.",
  GEOLOCATION_DENIED: "Location access was denied. Please enable location services.",
  FETCH_ERROR: "Failed to fetch weather data. Please try again.",
  API_ERROR: "Weather service is temporarily unavailable."
};

// Weather Icons Configuration
export const WEATHER_ICONS = {
  DEFAULT_SIZE: "@2x",
  LARGE_SIZE: "@4x"
};

// Local Storage Keys
export const STORAGE_KEYS = {
  SEARCH_HISTORY: "weatherSearchHistory",
  TEMPERATURE_UNIT: "temperatureUnit",
  USER_PREFERENCES: "weatherUserPreferences"
};

// Temperature Conversion Functions
export const convertTemperature = {
  toFahrenheit: (celsius) => (celsius * 9/5) + 32,
  toCelsius: (fahrenheit) => (fahrenheit - 32) * 5/9
};

// Weather Condition Categories
export const WEATHER_CATEGORIES = {
  CLEAR: ['01d', '01n'],
  PARTLY_CLOUDY: ['02d', '02n', '03d', '03n'],
  CLOUDY: ['04d', '04n'],
  RAIN: ['09d', '09n', '10d', '10n'],
  THUNDERSTORM: ['11d', '11n'],
  SNOW: ['13d', '13n'],
  MIST: ['50d', '50n']
};

// Air Quality Index Levels
export const AQI_LEVELS = {
  1: { label: 'Good', color: 'text-green-600', bg: 'bg-green-50' },
  2: { label: 'Fair', color: 'text-yellow-600', bg: 'bg-yellow-50' },
  3: { label: 'Moderate', color: 'text-orange-600', bg: 'bg-orange-50' },
  4: { label: 'Poor', color: 'text-red-600', bg: 'bg-red-50' },
  5: { label: 'Very Poor', color: 'text-purple-600', bg: 'bg-purple-50' }
};

// UV Index Categories
export const UV_INDEX = {
  LOW: { max: 2, color: 'text-green-600', advice: 'No protection required.' },
  MODERATE: { max: 5, color: 'text-yellow-600', advice: 'Wear sunscreen.' },
  HIGH: { max: 7, color: 'text-orange-600', advice: 'Seek shade during midday hours.' },
  VERY_HIGH: { max: 10, color: 'text-red-600', advice: 'Extra precautions needed.' },
  EXTREME: { max: Infinity, color: 'text-purple-600', advice: 'Avoid sun exposure.' }
};

// Weather Gradients
export const WEATHER_GRADIENTS = {
  day: 'weather-gradient',
  night: 'weather-gradient-night',
  cold: 'weather-gradient-cold',
  warm: 'weather-gradient-warm',
  rain: 'weather-gradient-rain'
};
