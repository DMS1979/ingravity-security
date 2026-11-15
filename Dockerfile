FROM node:22-alpine
WORKDIR /app
COPY package.json index.js index.d.ts mcp.js README.md ./
ENTRYPOINT ["node", "mcp.js"]
