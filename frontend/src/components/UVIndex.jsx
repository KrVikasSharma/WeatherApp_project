
import React from 'react';
import { motion } from 'framer-motion';
import { Sun } from 'lucide-react';
import { useWeather } from '@/contexts/WeatherContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const getUVLevel = (uv) => {
  if (uv <= 2) return { level: 'Low', color: 'text-green-600', bg: 'bg-green-50' };
  if (uv <= 5) return { level: 'Moderate', color: 'text-yellow-600', bg: 'bg-yellow-50' };
  if (uv <= 7) return { level: 'High', color: 'text-orange-600', bg: 'bg-orange-50' };
  if (uv <= 10) return { level: 'Very High', color: 'text-red-600', bg: 'bg-red-50' };
  return { level: 'Extreme', color: 'text-purple-600', bg: 'bg-purple-50' };
};

const UVIndex = () => {
  const { uvIndex } = useWeather();

  if (!uvIndex) {
    return null;
  }

  const { value } = uvIndex;
  const level = getUVLevel(value);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <Card className="weather-card w-full max-w-4xl mx-auto mt-6">
        <CardHeader className="pb-2 bg-blue-50 border-b border-blue-100">
          <CardTitle className="text-xl flex items-center">
            <Sun className="h-5 w-5 mr-2 text-blue-500" />
            UV Index
          </CardTitle>
        </CardHeader>
        <CardContent className="p-6">
          <div className="flex flex-col items-center">
            <div className={`text-3xl font-bold ${level.color} mb-2`}>
              {level.level}
            </div>
            <div className="text-xl font-semibold text-gray-700 mb-4">
              UV Index: {value}
            </div>
            <div className="w-full max-w-md bg-gray-200 rounded-full h-2.5">
              <div
                className="h-2.5 rounded-full transition-all duration-500"
                style={{
                  width: `${(value / 11) * 100}%`,
                  background: 'linear-gradient(to right, #22c55e, #eab308, #ef4444, #7c3aed)'
                }}
              />
            </div>
            <div className="mt-4 text-sm text-gray-600 text-center">
              {value <= 2 && "You can safely enjoy being outside!"}
              {value > 2 && value <= 5 && "Seek shade during midday hours! Wear sunscreen!"}
              {value > 5 && value <= 7 && "Reduce time in the sun between 10 a.m. and 4 p.m.!"}
              {value > 7 && value <= 10 && "Minimize sun exposure between 10 a.m. and 4 p.m.!"}
              {value > 10 && "Take all precautions. Unprotected skin can burn in minutes!"}
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
};

export default UVIndex;
