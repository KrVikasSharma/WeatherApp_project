
import React from 'react';
import { useWeather } from '@/contexts/WeatherContext';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';

const TemperatureUnitToggle = () => {
  const { temperatureUnit, toggleTemperatureUnit } = useWeather();

  return (
    <div className="flex items-center space-x-2">
      <Switch
        id="temperature-unit"
        checked={temperatureUnit === 'F'}
        onCheckedChange={toggleTemperatureUnit}
      />
      <Label htmlFor="temperature-unit" className="text-sm">
        {temperatureUnit === 'C' ? '°C' : '°F'}
      </Label>
    </div>
  );
};

export default TemperatureUnitToggle;
