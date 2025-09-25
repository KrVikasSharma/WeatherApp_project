# Stage 1: Build the frontend
FROM node:20-alpine AS build

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install

COPY . .
RUN npm run build

# Stage 2: Serve with Nginx
FROM nginx:alpine

# Copy build output to Nginx html directory
COPY --from=build /app/dist /usr/share/nginx/html

# Copy custom Nginx config if needed
# (otherwise Nginx default will serve index.html for /)
EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]`