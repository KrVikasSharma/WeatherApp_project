
import React from 'react';
import { motion } from 'framer-motion';
import { Sunrise, Sunset } from 'lucide-react';
import { useWeather } from '@/contexts/WeatherContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { format } from 'date-fns';

const SunriseSunset = () => {
  const { currentWeather } = useWeather();

  if (!currentWeather || !currentWeather.sys) {
    return null;
  }

  const { sunrise, sunset } = currentWeather.sys;
  const now = Date.now() / 1000;
  const sunriseDate = new Date(sunrise * 1000);
  const sunsetDate = new Date(sunset * 1000);
  
  // Calculate day progress percentage
  const dayLength = sunset - sunrise;
  const progress = Math.max(0, Math.min(100, ((now - sunrise) / dayLength) * 100));
  
  const isDaytime = now > sunrise && now < sunset;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <Card className="weather-card w-full max-w-4xl mx-auto mt-6">
        <CardHeader className="pb-2 bg-blue-50 border-b border-blue-100">
          <CardTitle className="text-xl flex items-center">
            {isDaytime ? (
              <Sunrise className="h-5 w-5 mr-2 text-blue-500" />
            ) : (
              <Sunset className="h-5 w-5 mr-2 text-blue-500" />
            )}
            Sunrise & Sunset
          </CardTitle>
        </CardHeader>
        <CardContent className="p-6">
          <div className="relative">
            {/* Sun arc background */}
            <div className="w-full h-32 bg-gradient-to-b from-blue-50 to-transparent rounded-t-full relative overflow-hidden">
              {/* Sun position indicator */}
              <div
                className="absolute bottom-0 w-6 h-6 bg-yellow-400 rounded-full shadow-lg transform -translate-x-1/2"
                style={{
                  left: `${progress}%`,
                  boxShadow: '0 0 20px rgba(250, 204, 21, 0.5)'
                }}
              />
              {/* Arc path */}
              <div className="absolute bottom-0 w-full h-full border-t-2 border-blue-200 rounded-t-full" />
            </div>
            
            {/* Time indicators */}
            <div className="flex justify-between mt-4">
              <div className="text-center">
                <Sunrise className="h-6 w-6 text-blue-500 mx-auto mb-1" />
                <div className="font-medium">Sunrise</div>
                <div className="text-sm text-gray-500">
                  {format(sunriseDate, 'h:mm a')}
                </div>
              </div>
              
              <div className="text-center">
                <Sunset className="h-6 w-6 text-blue-500 mx-auto mb-1" />
                <div className="font-medium">Sunset</div>
                <div className="text-sm text-gray-500">
                  {format(sunsetDate, 'h:mm a')}
                </div>
              </div>
            </div>
            
            {/* Day length */}
            <div className="text-center mt-4 text-sm text-gray-600">
              Day Length: {Math.round(dayLength / 3600)} hours{' '}
              {Math.round((dayLength % 3600) / 60)} minutes
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
};

export default SunriseSunset;
