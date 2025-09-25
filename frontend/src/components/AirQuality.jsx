
import React from 'react';
import { motion } from 'framer-motion';
import { Wind } from 'lucide-react';
import { useWeather } from '@/contexts/WeatherContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const getAQILevel = (aqi) => {
  const levels = {
    1: { label: 'Good', color: 'text-green-600', bg: 'bg-green-50' },
    2: { label: 'Fair', color: 'text-yellow-600', bg: 'bg-yellow-50' },
    3: { label: 'Moderate', color: 'text-orange-600', bg: 'bg-orange-50' },
    4: { label: 'Poor', color: 'text-red-600', bg: 'bg-red-50' },
    5: { label: 'Very Poor', color: 'text-purple-600', bg: 'bg-purple-50' }
  };
  return levels[aqi] || levels[1];
};

const AirQuality = () => {
  const { airQuality } = useWeather();

  if (!airQuality || !airQuality.list?.[0]) {
    return null;
  }

  const { main: { aqi }, components } = airQuality.list[0];
  const level = getAQILevel(aqi);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <Card className="weather-card w-full max-w-4xl mx-auto mt-6">
        <CardHeader className="pb-2 bg-blue-50 border-b border-blue-100">
          <CardTitle className="text-xl flex items-center">
            <Wind className="h-5 w-5 mr-2 text-blue-500" />
            Air Quality Index
          </CardTitle>
        </CardHeader>
        <CardContent className="p-6">
          <div className="flex flex-col md:flex-row items-center justify-between">
            <div className="text-center md:text-left mb-4 md:mb-0">
              <div className={`text-2xl font-bold ${level.color}`}>
                {level.label}
              </div>
              <div className="text-sm text-gray-500 mt-1">
                Air Quality Index: {aqi}
              </div>
            </div>
            
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              {Object.entries(components).map(([key, value]) => (
                <div
                  key={key}
                  className={`${level.bg} p-3 rounded-lg text-center`}
                >
                  <div className="text-sm font-medium text-gray-600">
                    {key.toUpperCase()}
                  </div>
                  <div className="text-lg font-bold text-gray-800">
                    {Math.round(value)}
                  </div>
                  <div className="text-xs text-gray-500">μg/m³</div>
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
};

export default AirQuality;
