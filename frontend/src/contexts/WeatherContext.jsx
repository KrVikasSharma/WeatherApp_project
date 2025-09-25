
import React, { createContext, useState, useContext, useEffect, useCallback } from 'react';
import { useToast } from '@/components/ui/use-toast';
import { WEATHER_API, ENDPOINTS, ERRORS } from '@/config/constants';

const WeatherContext = createContext(null);

export const useWeather = () => useContext(WeatherContext);

// Cache configuration
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes
const AQI_CACHE_DURATION = 30 * 60 * 1000; // 30 minutes

export const WeatherProvider = ({ children }) => {
  const [currentWeather, setCurrentWeather] = useState(null);
  const [forecast, setForecast] = useState(null);
  const [hourlyForecast, setHourlyForecast] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [searchHistory, setSearchHistory] = useState(() => {
    const saved = localStorage.getItem('weatherSearchHistory');
    return saved ? JSON.parse(saved) : [];
  });
  const [currentLocation, setCurrentLocation] = useState(null);
  const [temperatureUnit, setTemperatureUnit] = useState(() => {
    const saved = localStorage.getItem('temperatureUnit');
    return saved || 'C';
  });
  const [airQuality, setAirQuality] = useState(null);
  const [uvIndex, setUvIndex] = useState(null);
  const [weatherAlerts, setWeatherAlerts] = useState(null);
  const [lastAQIUpdate, setLastAQIUpdate] = useState(null);
  
  const { toast } = useToast();

  // Save search history to localStorage
  useEffect(() => {
    localStorage.setItem('weatherSearchHistory', JSON.stringify(searchHistory));
  }, [searchHistory]);

  // Save temperature unit preference
  useEffect(() => {
    localStorage.setItem('temperatureUnit', temperatureUnit);
  }, [temperatureUnit]);

  const toggleTemperatureUnit = () => {
    setTemperatureUnit(prev => prev === 'C' ? 'F' : 'C');
  };

  const convertTemperature = (celsius) => {
    if (temperatureUnit === 'F') {
      return (celsius * 9/5) + 32;
    }
    return celsius;
  };

  const fetchAirQuality = useCallback(async (lat, lon) => {
    // Check if we need to update AQI data
    if (lastAQIUpdate && Date.now() - lastAQIUpdate < AQI_CACHE_DURATION) {
      return airQuality;
    }

    try {
      const response = await fetch(
        `${WEATHER_API.BASE_URL}${ENDPOINTS.AIR_QUALITY}?lat=${lat}&lon=${lon}&appid=${WEATHER_API.KEY}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch air quality data');
      }
      
      const data = await response.json();
      setAirQuality(data);
      setLastAQIUpdate(Date.now());
      return data;
    } catch (error) {
      console.error('Air quality fetch error:', error);
      return null;
    }
  }, [lastAQIUpdate, airQuality]);

  const fetchUVIndex = async (lat, lon) => {
    try {
      const response = await fetch(
        `${WEATHER_API.BASE_URL}/uvi?lat=${lat}&lon=${lon}&appid=${WEATHER_API.KEY}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch UV index data');
      }
      
      const data = await response.json();
      setUvIndex(data);
      return data;
    } catch (error) {
      console.error('UV index fetch error:', error);
      return null;
    }
  };

  const fetchWeatherAlerts = async (lat, lon) => {
    try {
      const response = await fetch(
        `${WEATHER_API.BASE_URL}${ENDPOINTS.ONECALL}?lat=${lat}&lon=${lon}&exclude=current,minutely,hourly,daily&appid=${WEATHER_API.KEY}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch weather alerts');
      }
      
      const data = await response.json();
      setWeatherAlerts(data.alerts || []);
      return data.alerts || [];
    } catch (error) {
      console.error('Weather alerts fetch error:', error);
      return [];
    }
  };

  const fetchWeatherByCoords = async (lat, lon) => {
    try {
      setLoading(true);
      setError(null);
      
      // Fetch current weather
      const weatherResponse = await fetch(
        `${WEATHER_API.BASE_URL}${ENDPOINTS.WEATHER}?lat=${lat}&lon=${lon}&units=metric&appid=${WEATHER_API.KEY}`
      );
      
      if (!weatherResponse.ok) {
        throw new Error('Failed to fetch current weather');
      }
      
      const weatherData = await weatherResponse.json();
      setCurrentWeather(weatherData);
      
      // Fetch 5-day forecast
      const forecastResponse = await fetch(
        `${WEATHER_API.BASE_URL}${ENDPOINTS.FORECAST}?lat=${lat}&lon=${lon}&units=metric&appid=${WEATHER_API.KEY}`
      );
      
      if (!forecastResponse.ok) {
        throw new Error('Failed to fetch forecast');
      }
      
      const forecastData = await forecastResponse.json();
      
      // Process 5-day forecast (one entry per day)
      const dailyData = forecastData.list.filter((reading, index) => 
        index % 8 === 0 // Get one reading per day (every 24 hours)
      );
      setForecast(dailyData);
      
      // Process hourly forecast (next 24 hours)
      const hourlyData = forecastData.list.slice(0, 8); // Next 24 hours (3-hour intervals)
      setHourlyForecast(hourlyData);
      
      // Fetch additional data
      await Promise.all([
        fetchAirQuality(lat, lon),
        fetchUVIndex(lat, lon),
        fetchWeatherAlerts(lat, lon)
      ]);
      
      // Add to search history if it's a new location
      const locationName = weatherData.name;
      if (!searchHistory.some(item => item.name === locationName)) {
        const newLocation = {
          id: Date.now().toString(),
          name: locationName,
          lat,
          lon,
          country: weatherData.sys.country,
          timestamp: new Date().toISOString()
        };
        setSearchHistory(prev => [newLocation, ...prev].slice(0, 5));
      }
      
      return {
        current: weatherData,
        forecast: dailyData,
        hourly: hourlyData
      };
    } catch (error) {
      setError(error.message);
      toast({
        title: "Weather data fetch failed",
        description: error.message,
        variant: "destructive",
      });
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const fetchWeatherByCity = async (city) => {
    try {
      setLoading(true);
      setError(null);
      
      // Get coordinates for the city
      const geoResponse = await fetch(
        `${WEATHER_API.GEO_URL}${ENDPOINTS.GEOCODING}?q=${encodeURIComponent(city)}&limit=1&appid=${WEATHER_API.KEY}`
      );
      
      if (!geoResponse.ok) {
        throw new Error('Failed to find location');
      }
      
      const geoData = await geoResponse.json();
      
      if (!geoData.length) {
        throw new Error('Location not found');
      }
      
      const { lat, lon } = geoData[0];
      
      // Fetch weather using coordinates
      return await fetchWeatherByCoords(lat, lon);
    } catch (error) {
      setError(error.message);
      toast({
        title: "Weather data fetch failed",
        description: error.message,
        variant: "destructive",
      });
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const getCurrentLocationWeather = async () => {
    return new Promise((resolve, reject) => {
      if (!navigator.geolocation) {
        const error = new Error(ERRORS.GEOLOCATION_NOT_SUPPORTED);
        setError(error.message);
        toast({
          title: "Location error",
          description: error.message,
          variant: "destructive",
        });
        reject(error);
        return;
      }

      const handleSuccess = async (position) => {
        try {
          const { latitude: lat, longitude: lon } = position.coords;
          setCurrentLocation({ lat, lon });
          const data = await fetchWeatherByCoords(lat, lon);
          toast({
            title: "Location detected",
            description: `Weather loaded for ${data.current.name}`,
            variant: "default",
          });
          resolve(data);
        } catch (error) {
          reject(error);
        }
      };

      const handleError = (error) => {
        let errorMsg = ERRORS.FETCH_ERROR;
        if (error.code === 1) {
          errorMsg = ERRORS.GEOLOCATION_DENIED;
        }
        setError(errorMsg);
        toast({
          title: "Location error",
          description: errorMsg,
          variant: "destructive",
        });
        reject(new Error(errorMsg));
      };

      const options = {
        enableHighAccuracy: true,
        timeout: 10000,
        maximumAge: 0
      };

      navigator.geolocation.getCurrentPosition(handleSuccess, handleError, options);
    });
  };

  const clearSearchHistory = () => {
    setSearchHistory([]);
    localStorage.removeItem('weatherSearchHistory');
    toast({
      title: "Search history cleared",
      description: "Your search history has been cleared",
      variant: "default",
    });
  };

  const value = {
    currentWeather,
    forecast,
    hourlyForecast,
    loading,
    error,
    searchHistory,
    currentLocation,
    temperatureUnit,
    airQuality,
    uvIndex,
    weatherAlerts,
    fetchWeatherByCity,
    fetchWeatherByCoords,
    getCurrentLocationWeather,
    clearSearchHistory,
    toggleTemperatureUnit,
    convertTemperature,
  };

  return <WeatherContext.Provider value={value}>{children}</WeatherContext.Provider>;
};
