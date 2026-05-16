# Imagen base
FROM node:18-alpine

# Crear directorio de trabajo
WORKDIR /app

# Copiar package.json y package-lock.json
COPY package*.json ./

# Instalar dependencias (incluye better-sqlite3)
RUN apk add --no-cache python3 make g++ \
    && npm install \
    && apk del python3 make g++

# Copiar todo el proyecto
COPY . .

# Exponer el puerto (ajusta si tu app usa otro)
EXPOSE 3000

# Comando de inicio
CMD ["node", "server.js"]
