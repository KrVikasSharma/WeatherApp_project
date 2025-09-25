
import React, { useState } from 'react';
import { Search, MapPin, History, X } from 'lucide-react';
import { motion } from 'framer-motion';
import { useWeather } from '@/contexts/WeatherContext';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/components/ui/use-toast';

const WeatherSearch = () => {
  const [query, setQuery] = useState('');
  const [showHistory, setShowHistory] = useState(false);
  const { 
    fetchWeatherByCity, 
    fetchWeatherByCoords,
    getCurrentLocationWeather, 
    searchHistory, 
    clearSearchHistory,
    loading 
  } = useWeather();
  const { toast } = useToast();

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!query.trim()) {
      toast({
        title: "Search error",
        description: "Please enter a city name",
        variant: "destructive",
      });
      return;
    }

    try {
      await fetchWeatherByCity(query);
      setQuery('');
      setShowHistory(false);
    } catch (error) {
      // Error is already handled in the context
    }
  };

  const handleLocationClick = async () => {
    try {
      await getCurrentLocationWeather();
      setShowHistory(false);
    } catch (error) {
      // Error is already handled in the context
    }
  };

  const handleHistoryItemClick = async (item) => {
    try {
      await fetchWeatherByCoords(item.lat, item.lon);
      setShowHistory(false);
    } catch (error) {
      // Error is already handled in the context
    }
  };

  return (
    <div className="relative w-full max-w-md mx-auto">
      <form onSubmit={handleSearch} className="relative">
        <div className="relative flex items-center">
          <Input
            type="text"
            placeholder="Search for a city..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pr-24 pl-10 h-12 bg-white/80 backdrop-blur-sm border-blue-200 focus:border-blue-400 rounded-full shadow-md"
          />
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-blue-500 h-5 w-5" />
          
          <div className="absolute right-2 flex space-x-1">
            <Button
              type="button"
              size="icon"
              variant="ghost"
              className="h-8 w-8 rounded-full bg-blue-100 hover:bg-blue-200"
              onClick={() => setShowHistory(!showHistory)}
            >
              <History className="h-4 w-4 text-blue-700" />
            </Button>
            
            <Button
              type="button"
              size="icon"
              variant="ghost"
              className="h-8 w-8 rounded-full bg-blue-100 hover:bg-blue-200"
              onClick={handleLocationClick}
              disabled={loading}
            >
              <MapPin className="h-4 w-4 text-blue-700" />
            </Button>
            
            <Button
              type="submit"
              size="sm"
              className="rounded-full h-8 px-3 bg-blue-500 hover:bg-blue-600"
              disabled={loading}
            >
              {loading ? 'Loading...' : 'Search'}
            </Button>
          </div>
        </div>
      </form>

      {/* Search History Dropdown */}
      {showHistory && searchHistory.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -10 }}
          className="absolute z-10 mt-2 w-full bg-white rounded-lg shadow-lg border border-blue-100 overflow-hidden"
        >
          <div className="p-2 flex justify-between items-center border-b border-blue-100">
            <h3 className="text-sm font-medium text-gray-700">Recent Searches</h3>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-xs text-red-500 hover:text-red-700 hover:bg-red-50"
              onClick={clearSearchHistory}
            >
              Clear All
            </Button>
          </div>
          <ul className="max-h-60 overflow-auto">
            {searchHistory.map((item) => (
              <li key={item.id} className="border-b border-blue-50 last:border-0">
                <button
                  className="w-full px-4 py-2 text-left hover:bg-blue-50 flex items-center justify-between"
                  onClick={() => handleHistoryItemClick(item)}
                >
                  <div className="flex items-center">
                    <MapPin className="h-4 w-4 text-blue-500 mr-2" />
                    <span>{item.name}, {item.country}</span>
                  </div>
                  <span className="text-xs text-gray-500">
                    {new Date(item.timestamp).toLocaleDateString()}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </motion.div>
      )}
    </div>
  );
};

export default WeatherSearch;
