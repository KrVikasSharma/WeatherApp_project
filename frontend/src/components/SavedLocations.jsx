
import React from 'react';
import { motion } from 'framer-motion';
import { MapPin, Trash2 } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { useWeather } from '@/contexts/WeatherContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

const SavedLocations = () => {
  const { user, removeLocation } = useAuth();
  const { fetchWeatherByCoords } = useWeather();
  
  const savedLocations = user?.savedLocations || [];
  
  if (savedLocations.length === 0) {
    return (
      <Card className="weather-card w-full">
        <CardHeader className="pb-2">
          <CardTitle className="text-xl">Saved Locations</CardTitle>
        </CardHeader>
        <CardContent className="text-center py-8">
          <p className="text-gray-500">You haven't saved any locations yet.</p>
          <p className="text-sm text-gray-400 mt-2">
            Search for a location and save it to view it here.
          </p>
        </CardContent>
      </Card>
    );
  }
  
  return (
    <Card className="weather-card w-full">
      <CardHeader className="pb-2 bg-blue-50 border-b border-blue-100">
        <CardTitle className="text-xl">Saved Locations</CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <ul className="divide-y divide-blue-100">
          {savedLocations.map((location, index) => (
            <motion.li
              key={location.id}
              className="p-4 hover:bg-blue-50 transition-colors"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: index * 0.1 }}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  <MapPin className="h-5 w-5 text-blue-500 mr-2" />
                  <div>
                    <div className="font-medium">{location.name}, {location.country}</div>
                    <div className="text-xs text-gray-500">
                      Saved on {new Date(location.timestamp).toLocaleDateString()}
                    </div>
                  </div>
                </div>
                <div className="flex space-x-2">
                  <Button
                    variant="outline"
                    size="sm"
                    className="text-blue-600 border-blue-200 hover:bg-blue-50"
                    onClick={() => fetchWeatherByCoords(location.lat, location.lon)}
                  >
                    View Weather
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-red-500 hover:bg-red-50 hover:text-red-600"
                    onClick={() => removeLocation(location.id)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </motion.li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
};

export default SavedLocations;
