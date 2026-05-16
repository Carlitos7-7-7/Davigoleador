# Usa una imagen ligera de nginx
FROM nginx:alpine

# Copiar tu sitio al directorio estándar de nginx
COPY . /usr/share/nginx/html

# Exponer el puerto 80
EXPOSE 80

# Comando por defecto: ejecutar nginx en primer plano
CMD ["nginx", "-g", "daemon off;"]
