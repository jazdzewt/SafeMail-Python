FROM nginx:latest

# Kopiujemy config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Kopiujemy certyfikaty
COPY cert.pem /etc/nginx/ssl/cert.pem
COPY key.pem /etc/nginx/ssl/key.pem

# Zmieniamy właściciela certyfikatów i folderów tymczasowych na użytkownika 'nginx'
RUN chown -R nginx:nginx /etc/nginx/ssl

RUN chown -R nginx:nginx /var/cache/nginx && \
    chown -R nginx:nginx /var/log/nginx && \
    chown -R nginx:nginx /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && \
    chown -R nginx:nginx /var/run/nginx.pid

USER nginx