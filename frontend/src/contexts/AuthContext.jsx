import React, { createContext, useState, useEffect, useContext } from "react";
import { useToast } from "@/components/ui/use-toast";
import axios from "axios";

// 👇 Import your backend API config from constants.js
import { LOCAL_API } from "@/config/constants";

const AuthContext = createContext(null);

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  // 👇 Use single source of truth for backend URL
  const API_URL = LOCAL_API.BASE_URL + "/auth";

  useEffect(() => {
  const storedUser = localStorage.getItem("weatherAppUser");
  if (storedUser) {
    try {
      const parsed = JSON.parse(storedUser);
      setUser(parsed.user); // <-- FIX: use the inner user object
    } catch (error) {
      console.error("Failed to parse stored user:", error);
      localStorage.removeItem("weatherAppUser");
    }
  }
  setLoading(false);
}, []);


  // Registration
  const register = async (email, password, name) => {
    try {
      setLoading(true);
      const response = await axios.post(`${API_URL}/signup`, {
        email,
        password,
        name,
      });
      const userData = response.data;
      setUser(userData);
      localStorage.setItem("weatherAppUser", JSON.stringify(userData));
      toast({
        title: "Registration successful",
        description: "Welcome to Weather App!",
        variant: "default",
      });
      return userData;
    } catch (error) {
      toast({
        title: "Registration failed",
        description:
          error.response?.data?.error ||
          error.message ||
          "Something went wrong",
        variant: "destructive",
      });
      throw error;
    } finally {
      setLoading(false);
    }
  };

  // Login
  const login = async (email, password) => {
    try {
      setLoading(true);
      const response = await axios.post(`${API_URL}/login`, {
        email,
        password,
      });
      const userData = response.data;
      setUser(userData);
      localStorage.setItem("weatherAppUser", JSON.stringify(userData));
      toast({
        title: "Login successful",
        description: `Welcome back, ${userData.name}!`,
        variant: "default",
      });
      return userData;
    } catch (error) {
      toast({
        title: "Login failed",
        description:
          error.response?.data?.error ||
          error.message ||
          "Something went wrong",
        variant: "destructive",
      });
      throw error;
    } finally {
      setLoading(false);
    }
  };

  // Logout
  const logout = () => {
    setUser(null);
    localStorage.removeItem("weatherAppUser");
    toast({
      title: "Logged out",
      description: "You have been logged out successfully",
      variant: "default",
    });
  };

  const saveLocation = (location) => {
  setUser(prevUser => {
    const updatedUser = {
      ...prevUser,
      savedLocations: [...(prevUser.savedLocations || []), location]
    };
    localStorage.setItem("weatherAppUser", JSON.stringify({ user: updatedUser, token: userToken }));
    return updatedUser;
  });
};


  const value = {
    user,
    loading,
    register,
    login,
    logout,
    isAuthenticated: !!user,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
