FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
COPY packages/sdk-js/package.json ./packages/sdk-js/package.json
COPY packages/connector-sdk/package.json ./packages/connector-sdk/package.json
COPY packages/provider-sdk/package.json ./packages/provider-sdk/package.json
RUN npm ci --ignore-scripts
COPY . .
RUN npm run check

FROM node:24-bookworm-slim AS runtime
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000
WORKDIR /app
COPY package*.json ./
COPY packages/sdk-js/package.json ./packages/sdk-js/package.json
COPY packages/connector-sdk/package.json ./packages/connector-sdk/package.json
COPY packages/provider-sdk/package.json ./packages/provider-sdk/package.json
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY --from=build /app/dist ./dist
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s CMD node -e "fetch('http://127.0.0.1:3000/readyz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node","dist/server.js"]
