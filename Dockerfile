# Use the PHP image
FROM php:8.2-cli

# Install git and unzip (if needed)
RUN apt-get update && apt-get install -y git unzip

# Copy the composer binary
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Set the working directory
WORKDIR /var/www

# Copy the application files
COPY . .

# Install dependencies using Composer
RUN composer install

# Expose the WebSocket port (optional, based on your app configuration)
EXPOSE 10000
