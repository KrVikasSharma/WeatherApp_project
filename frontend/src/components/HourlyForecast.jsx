
import React from 'react';
import { motion } from 'framer-motion';
import { useWeather } from '@/contexts/WeatherContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Clock } from 'lucide-react';

const HourlyForecast = () => {
  const { hourlyForecast, loading } = useWeather();

  if (loading) {
    return (
      <Card className="weather-card w-full max-w-4xl mx-auto mt-6">
        <CardHeader className="pb-2">
          <CardTitle className="text-xl">Loading hourly forecast...</CardTitle>
        </CardHeader>
        <CardContent className="py-4">
          <div className="animate-pulse flex space-x-4 overflow-x-auto pb-2">
            {[...Array(8)].map((_, i) => (
              <div key={i} className="flex-shrink-0 w-24 flex flex-col items-center">
                <div className="h-4 bg-blue-200 rounded w-16 mb-2"></div>
                <div className="h-12 w-12 bg-blue-200 rounded-full mb-2"></div>
                <div className="h-6 bg-blue-200 rounded w-12"></div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!hourlyForecast || hourlyForecast.length === 0) {
    return null;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.2 }}
    >
      <Card className="weather-card w-full max-w-4xl mx-auto mt-6 overflow-hidden">
        <CardHeader className="pb-2 bg-blue-50 border-b border-blue-100">
          <CardTitle className="text-xl flex items-center">
            <Clock className="h-5 w-5 mr-2 text-blue-500" />
            Hourly Forecast
          </CardTitle>
        </CardHeader>
        <CardContent className="p-4">
          <div className="flex space-x-4 overflow-x-auto pb-2">
            {hourlyForecast.map((hour, index) => {
              const date = new Date(hour.dt * 1000);
              const time = date.toLocaleTimeString('en-US', {
                hour: '2-digit',
                minute: '2-digit',
              });
              const temp = Math.round(hour.main.temp);
              const icon = `https://openweathermap.org/img/wn/${hour.weather[0].icon}.png`;
              
              return (
                <motion.div
                  key={hour.dt}
                  className="flex-shrink-0 w-24 flex flex-col items-center p-3 rounded-lg hover:bg-blue-50 transition-colors"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.3, delay: 0.1 * index }}
                >
                  <div className="text-sm font-medium text-gray-600 mb-1">{time}</div>
                  <img src={icon} alt={hour.weather[0].description} className="h-12 w-12 my-1" />
                  <div className="text-lg font-bold">{temp}°C</div>
                  <div className="text-xs text-gray-500 mt-1 text-center">
                    {hour.weather[0].main}
                  </div>
                  <div className="text-xs text-blue-500 mt-1">
                    {Math.round(hour.pop * 100)}% <span className="text-gray-400">rain</span>
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

export default HourlyForecast;
