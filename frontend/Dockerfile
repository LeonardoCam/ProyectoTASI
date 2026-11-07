FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npx ng build --configuration production

FROM nginx:alpine
COPY --from=build /app/dist/frontend/browser /usr/share/nginx/html
RUN cp /usr/share/nginx/html/index.csr.html /usr/share/nginx/html/index.html || true
EXPOSE 80
