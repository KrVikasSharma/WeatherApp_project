
import React from 'react';
import { motion } from 'framer-motion';
import { useWeather } from '@/contexts/WeatherContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { MapPin, Wind, Droplets, Thermometer, Clock, Calendar } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';

const CurrentWeather = () => {
  const { currentWeather, loading } = useWeather();
  const { user, saveLocation, isAuthenticated } = useAuth();
  
  if (loading) {
    return (
      <Card className="weather-card w-full max-w-md mx-auto">
        <CardHeader className="pb-2">
          <CardTitle className="text-xl text-center">Loading weather data...</CardTitle>
        </CardHeader>
        <CardContent className="flex justify-center py-8">
          <div className="animate-pulse flex flex-col items-center">
            <div className="h-24 w-24 bg-blue-200 rounded-full mb-4"></div>
            <div className="h-8 w-48 bg-blue-200 rounded mb-2"></div>
            <div className="h-6 w-32 bg-blue-200 rounded"></div>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!currentWeather) {
    return (
      <Card className="weather-card w-full max-w-md mx-auto">
        <CardHeader className="pb-2">
          <CardTitle className="text-xl text-center">No weather data</CardTitle>
        </CardHeader>
        <CardContent className="text-center py-8">
          <p>Search for a city or use your current location to see weather information.</p>
        </CardContent>
      </Card>
    );
  }

  const {
    name,
    main: { temp, feels_like, humidity, temp_min, temp_max, pressure },
    weather,
    wind,
    sys,
    dt
  } = currentWeather;

  const weatherIcon = `https://openweathermap.org/img/wn/${weather[0].icon}@4x.png`;
  const date = new Date(dt * 1000);
  const formattedDate = date.toLocaleDateString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });
  const formattedTime = date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit'
  });

  const getWeatherGradient = () => {
    const icon = weather[0].icon;
    if (icon.includes('n')) return 'weather-gradient-night';
    if (icon.includes('01') || icon.includes('02')) return 'weather-gradient';
    if (icon.includes('03') || icon.includes('04')) return 'weather-gradient-cold';
    if (icon.includes('09') || icon.includes('10') || icon.includes('11')) return 'weather-gradient-rain';
    if (temp > 25) return 'weather-gradient-warm';
    return 'weather-gradient';
  };

  const handleSaveLocation = () => {
    const locationToSave = {
      id: Date.now().toString(),
      name,
      country: sys.country,
      lat: currentWeather.coord.lat,
      lon: currentWeather.coord.lon,
      timestamp: new Date().toISOString()
    };
    saveLocation(locationToSave);
  };

  const isSaved = user?.savedLocations?.some(loc => 
    loc.name === name && loc.country === sys.country
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <Card className={`weather-card w-full max-w-md mx-auto overflow-hidden`}>
        <div className={`${getWeatherGradient()} text-white p-6 pb-8`}>
          <div className="flex justify-between items-start">
            <div>
              <h2 className="text-3xl font-bold">{name}, {sys.country}</h2>
              <div className="flex items-center mt-1 text-white/90">
                <MapPin className="h-4 w-4 mr-1" />
                <span className="text-sm">
                  {currentWeather.coord.lat.toFixed(2)}°, {currentWeather.coord.lon.toFixed(2)}°
                </span>
              </div>
              <div className="flex items-center mt-3 space-x-2">
                <Calendar className="h-4 w-4" />
                <span className="text-sm">{formattedDate}</span>
              </div>
              <div className="flex items-center mt-1 space-x-2">
                <Clock className="h-4 w-4" />
                <span className="text-sm">Updated at {formattedTime}</span>
              </div>
            </div>
            <img 
              src={weatherIcon} 
              alt={weather[0].description} 
              className="h-20 w-20 object-contain"
            />
          </div>
          
          <div className="mt-4 flex items-end">
            <div className="text-6xl font-bold">{Math.round(temp)}°</div>
            <div className="ml-2 mb-1 text-lg">C</div>
          </div>
          
          <div className="mt-1 capitalize text-lg font-medium">
            {weather[0].description}
          </div>
          
          <div className="mt-4 text-sm">
            Feels like {Math.round(feels_like)}°C • Min {Math.round(temp_min)}°C • Max {Math.round(temp_max)}°C
          </div>
        </div>
        
        <CardContent className="p-6">
          <div className="grid grid-cols-3 gap-4">
            <div className="flex flex-col items-center p-3 bg-blue-50 rounded-lg">
              <Wind className="h-6 w-6 text-blue-500 mb-2" />
              <div className="text-sm font-medium">Wind</div>
              <div className="text-lg font-bold">{wind.speed} m/s</div>
            </div>
            
            <div className="flex flex-col items-center p-3 bg-blue-50 rounded-lg">
              <Droplets className="h-6 w-6 text-blue-500 mb-2" />
              <div className="text-sm font-medium">Humidity</div>
              <div className="text-lg font-bold">{humidity}%</div>
            </div>
            
            <div className="flex flex-col items-center p-3 bg-blue-50 rounded-lg">
              <Thermometer className="h-6 w-6 text-blue-500 mb-2" />
              <div className="text-sm font-medium">Pressure</div>
              <div className="text-lg font-bold">{pressure} hPa</div>
            </div>
          </div>
          
          {isAuthenticated && (
            <div className="mt-4 flex justify-center">
              <Button
                variant={isSaved ? "outline" : "default"}
                className={isSaved ? "border-blue-300 text-blue-700" : ""}
                onClick={handleSaveLocation}
                disabled={isSaved}
              >
                {isSaved ? "Location Saved" : "Save Location"}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
};

export default CurrentWeather;
