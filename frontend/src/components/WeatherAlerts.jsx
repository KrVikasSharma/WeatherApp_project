
import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle } from 'lucide-react';
import { useWeather } from '@/contexts/WeatherContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

const WeatherAlerts = () => {
  const { weatherAlerts } = useWeather();

  if (!weatherAlerts || weatherAlerts.length === 0) {
    return null;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      <Card className="weather-card w-full max-w-4xl mx-auto mt-6 border-yellow-200">
        <CardHeader className="pb-2 bg-yellow-50 border-b border-yellow-100">
          <CardTitle className="text-xl flex items-center text-yellow-700">
            <AlertTriangle className="h-5 w-5 mr-2 text-yellow-600" />
            Weather Alerts
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <AnimatePresence>
            {weatherAlerts.map((alert, index) => (
              <motion.div
                key={alert.event + index}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                transition={{ duration: 0.3, delay: index * 0.1 }}
                className="p-4 border-b border-yellow-100 last:border-b-0"
              >
                <div className="flex items-start space-x-4">
                  <AlertTriangle className="h-5 w-5 text-yellow-500 mt-1 flex-shrink-0" />
                  <div>
                    <h4 className="font-medium text-yellow-700">{alert.event}</h4>
                    <p className="text-sm text-gray-600 mt-1">{alert.description}</p>
                    <div className="flex items-center space-x-4 mt-2 text-xs text-gray-500">
                      <span>
                        From: {new Date(alert.start * 1000).toLocaleString()}
                      </span>
                      <span>
                        Until: {new Date(alert.end * 1000).toLocaleString()}
                      </span>
                    </div>
                  </div>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </CardContent>
      </Card>
    </motion.div>
  );
};

export default WeatherAlerts;
