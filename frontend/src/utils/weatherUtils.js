
import { WEATHER_CATEGORIES, UV_INDEX, AQI_LEVELS } from '@/config/constants';

// Format temperature based on unit
export const formatTemperature = (temp, unit = 'C') => {
  const temperature = unit === 'F' ? (temp * 9/5) + 32 : temp;
  return `${Math.round(temperature)}°${unit}`;
};

// Get weather gradient based on conditions
export const getWeatherGradient = (iconCode, temperature) => {
  if (iconCode.includes('n')) return 'weather-gradient-night';
  if (WEATHER_CATEGORIES.CLEAR.includes(iconCode)) return 'weather-gradient';
  if (WEATHER_CATEGORIES.CLOUDY.includes(iconCode)) return 'weather-gradient-cold';
  if (WEATHER_CATEGORIES.RAIN.includes(iconCode)) return 'weather-gradient-rain';
  return temperature > 25 ? 'weather-gradient-warm' : 'weather-gradient';
};

// Format wind direction
export const getWindDirection = (degrees) => {
  const directions = ['N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE', 'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW'];
  const index = Math.round(degrees / 22.5) % 16;
  return directions[index];
};

// Get UV index category
export const getUVCategory = (uvIndex) => {
  if (uvIndex <= UV_INDEX.LOW.max) return UV_INDEX.LOW;
  if (uvIndex <= UV_INDEX.MODERATE.max) return UV_INDEX.MODERATE;
  if (uvIndex <= UV_INDEX.HIGH.max) return UV_INDEX.HIGH;
  if (uvIndex <= UV_INDEX.VERY_HIGH.max) return UV_INDEX.VERY_HIGH;
  return UV_INDEX.EXTREME;
};

// Get AQI level information
export const getAQILevel = (aqi) => {
  return AQI_LEVELS[aqi] || AQI_LEVELS[1];
};

// Format precipitation chance
export const formatPrecipitation = (pop) => {
  return `${Math.round(pop * 100)}%`;
};

// Format date and time
export const formatDateTime = (timestamp, type = 'full') => {
  const date = new Date(timestamp * 1000);
  
  const options = {
    full: {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    },
    short: {
      month: 'short',
      day: 'numeric'
    },
    time: {
      hour: '2-digit',
      minute: '2-digit'
    }
  };

  return date.toLocaleDateString('en-US', options[type]);
};

// Calculate day length in hours and minutes
export const calculateDayLength = (sunrise, sunset) => {
  const dayLength = sunset - sunrise;
  const hours = Math.floor(dayLength / 3600);
  const minutes = Math.round((dayLength % 3600) / 60);
  return { hours, minutes };
};

// Format visibility
export const formatVisibility = (visibility) => {
  return `${(visibility / 1000).toFixed(1)} km`;
};

// Get weather description with proper capitalization
export const formatWeatherDescription = (description) => {
  return description.split(' ')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
};
