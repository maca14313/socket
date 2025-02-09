# Use official PHP image with sockets enabled
FROM php:8.2-cli

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /var/www

# Copy app files
COPY . .

# Install dependencies
RUN composer install

# Expose WebSocket port (make sure to match this with Render's port)
EXPOSE 10000

# Run WebSocket server
CMD ["php", "server.php"]
