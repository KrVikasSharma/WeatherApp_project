# Use a small Node base
FROM node:20-alpine

# Create app directory
WORKDIR /usr/src/app

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm ci --production

# Copy source
COPY . .

# Build step not needed but keep ownership correct
RUN chown -R node:node /usr/src/app
USER node

ENV NODE_ENV=production
EXPOSE 4000

CMD ["node", "server.js"]