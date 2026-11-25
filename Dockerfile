FROM node:22-alpine
WORKDIR /app
COPY package.json index.js index.d.ts mcp.js README.md AGENTS.md server.json glama.json ./
USER node
ENTRYPOINT ["node", "/app/mcp.js"]
