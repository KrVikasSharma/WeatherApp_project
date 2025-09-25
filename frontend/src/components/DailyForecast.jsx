
import React from 'react';
import { motion } from 'framer-motion';
import { useWeather } from '@/contexts/WeatherContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Calendar, Droplets, Thermometer, Wind } from 'lucide-react';

const DailyForecast = () => {
  const { forecast, loading } = useWeather();

  if (loading) {
    return (
      <Card className="weather-card w-full max-w-4xl mx-auto mt-6">
        <CardHeader className="pb-2">
          <CardTitle className="text-xl">Loading 5-day forecast...</CardTitle>
        </CardHeader>
        <CardContent className="py-4">
          <div className="animate-pulse space-y-4">
            {[...Array(5)].map((_, i) => (
              <div key={i} className="h-20 bg-blue-100 rounded-lg"></div>
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!forecast || forecast.length === 0) {
    return null;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.3 }}
    >
      <Card className="weather-card w-full max-w-4xl mx-auto mt-6 overflow-hidden">
        <CardHeader className="pb-2 bg-blue-50 border-b border-blue-100">
          <CardTitle className="text-xl flex items-center">
            <Calendar className="h-5 w-5 mr-2 text-blue-500" />
            5-Day Forecast
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="divide-y divide-blue-100">
            {forecast.map((day, index) => {
              const date = new Date(day.dt * 1000);
              const dayName = date.toLocaleDateString('en-US', { weekday: 'long' });
              const formattedDate = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
              const icon = `https://openweathermap.org/img/wn/${day.weather[0].icon}.png`;
              
              return (
                <motion.div
                  key={day.dt}
                  className="p-4 hover:bg-blue-50 transition-colors"
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.3, delay: 0.1 * index }}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-4">
                      <div className="w-20 text-left">
                        <div className="font-bold">{dayName}</div>
                        <div className="text-sm text-gray-500">{formattedDate}</div>
                      </div>
                      
                      <img src={icon} alt={day.weather[0].description} className="h-12 w-12" />
                      
                      <div className="w-32">
                        <div className="font-medium capitalize">{day.weather[0].description}</div>
                        <div className="text-sm text-gray-500">
                          {Math.round(day.pop * 100)}% chance of rain
                        </div>
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-6">
                      <div className="flex items-center">
                        <Thermometer className="h-4 w-4 text-blue-500 mr-1" />
                        <span className="font-bold">{Math.round(day.main.temp)}°C</span>
                      </div>
                      
                      <div className="flex items-center">
                        <Wind className="h-4 w-4 text-blue-500 mr-1" />
                        <span>{day.wind.speed} m/s</span>
                      </div>
                      
                      <div className="flex items-center">
                        <Droplets className="h-4 w-4 text-blue-500 mr-1" />
                        <span>{day.main.humidity}%</span>
                      </div>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
};

export default DailyForecast;
