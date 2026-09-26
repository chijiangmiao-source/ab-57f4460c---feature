FROM node:20-alpine

WORKDIR /app

# 零第三方依赖：直接复制源码与静态资源
COPY package.json ./
COPY src ./src
COPY public ./public
COPY tests ./tests
COPY scripts ./scripts
COPY verify ./verify

ENV NODE_ENV=production \
    PORT=8080 \
    HOST=0.0.0.0

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]
