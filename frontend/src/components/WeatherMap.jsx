
import React, { useEffect, useRef } from 'react';
import { Map, View } from 'ol';
import TileLayer from 'ol/layer/Tile';
import OSM from 'ol/source/OSM';
import { fromLonLat } from 'ol/proj';
import { useWeather } from '@/contexts/WeatherContext';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { MapPin } from 'lucide-react';
import 'ol/ol.css';

const WeatherMap = () => {
  const mapRef = useRef();
  const mapInstanceRef = useRef(null);
  const { currentWeather } = useWeather();

  useEffect(() => {
    if (!mapInstanceRef.current) {
      mapInstanceRef.current = new Map({
        target: mapRef.current,
        layers: [
          new TileLayer({
            source: new OSM()
          })
        ],
        view: new View({
          center: fromLonLat([0, 0]),
          zoom: 2
        })
      });
    }

    // Update map center when weather data changes
    if (currentWeather?.coord) {
      const { lon, lat } = currentWeather.coord;
      mapInstanceRef.current.getView().animate({
        center: fromLonLat([lon, lat]),
        zoom: 10,
        duration: 1000
      });
    }

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.setTarget(undefined);
        mapInstanceRef.current = null;
      }
    };
  }, [currentWeather]);

  return (
    <Card className="weather-card w-full max-w-4xl mx-auto mt-6">
      <CardHeader className="pb-2 bg-blue-50 border-b border-blue-100">
        <CardTitle className="text-xl flex items-center">
          <MapPin className="h-5 w-5 mr-2 text-blue-500" />
          Weather Map
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div 
          ref={mapRef} 
          className="h-[400px] w-full rounded-b-lg"
          style={{ background: '#f8fafc' }}
        />
      </CardContent>
    </Card>
  );
};

export default WeatherMap;
