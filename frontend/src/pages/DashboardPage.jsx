import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import WeatherSearch from '@/components/WeatherSearch';
import CurrentWeather from '@/components/CurrentWeather';
import HourlyForecast from '@/components/HourlyForecast';
import DailyForecast from '@/components/DailyForecast';
import SavedLocations from '@/components/SavedLocations';
import { useAuth } from '@/contexts/AuthContext';
import { useWeather } from '@/contexts/WeatherContext';

const DashboardPage = () => {
  const { user, isAuthenticated, loading: authLoading } = useAuth();
  const { getCurrentLocationWeather, currentWeather } = useWeather();
  const navigate = useNavigate();

  useEffect(() => {
    // Redirect to login if not authenticated
    if (!authLoading && !isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, authLoading, navigate]);

  useEffect(() => {
    // Try to get weather for current location when the page loads
    if (isAuthenticated && !currentWeather) {
      getCurrentLocationWeather().catch(() => {
        // Error is already handled in the context
      });
    }
  }, [isAuthenticated]);

  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return null; // Will redirect to login
  }

  // Safely display user name (fallback: "User")
  const userName = user && user.name ? user.name : "User";

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar />

      <main className="flex-grow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="mb-8"
          >
            <h1 className="text-3xl font-bold text-blue-800 mb-2">
              Welcome, {userName}!
            </h1>
            <p className="text-gray-600">
              View your saved locations and check the weather forecast.
            </p>
          </motion.div>

          <Tabs defaultValue="weather" className="w-full">
            <TabsList className="w-full max-w-md mx-auto mb-6">
              <TabsTrigger value="weather" className="flex-1">Current Weather</TabsTrigger>
              <TabsTrigger value="saved" className="flex-1">Saved Locations</TabsTrigger>
            </TabsList>

            <TabsContent value="weather" className="space-y-6">
              <div className="mb-8">
                <WeatherSearch />
              </div>

              <CurrentWeather />
              <HourlyForecast />
              <DailyForecast />
            </TabsContent>

            <TabsContent value="saved">
              <SavedLocations />
            </TabsContent>
          </Tabs>
        </div>
      </main>

      <Footer />
    </div>
  );
};

export default DashboardPage;
