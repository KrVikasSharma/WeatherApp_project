
import React, { useEffect } from 'react';
import { motion } from 'framer-motion';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import WeatherSearch from '@/components/WeatherSearch';
import CurrentWeather from '@/components/CurrentWeather';
import HourlyForecast from '@/components/HourlyForecast';
import DailyForecast from '@/components/DailyForecast';
import WeatherMap from '@/components/WeatherMap';
import AirQuality from '@/components/AirQuality';
import { useWeather } from '@/contexts/WeatherContext';

const HomePage = () => {
  const { getCurrentLocationWeather, currentWeather } = useWeather();

  useEffect(() => {
    // Try to get weather for current location when the page loads
    if (!currentWeather) {
      getCurrentLocationWeather().catch(() => {
        // Error is already handled in the context
      });
    }
  }, []);

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />
      
      <main className="flex-grow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="text-center mb-8"
          >
            <h1 className="text-3xl md:text-4xl font-bold text-blue-800 mb-2">
              Weather Forecast
            </h1>
            <p className="text-gray-600 max-w-2xl mx-auto">
              Get accurate weather information for any location. Plan your day with confidence using our detailed weather forecasts.
            </p>
          </motion.div>
          
          <div className="mb-8">
            <WeatherSearch />
          </div>
          
          <div className="space-y-6">
            <CurrentWeather />
            <WeatherMap />
            <HourlyForecast />
            <DailyForecast />
            <AirQuality />
          </div>
        </div>
      </main>
      
      <Footer />
    </div>
  );
};

export default HomePage;
