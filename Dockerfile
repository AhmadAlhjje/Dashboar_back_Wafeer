# ── لوحة تحكم وفير — الباك اند (Express + TypeScript) ─────────────────────────
# بناء على مرحلتين: الأولى تترجم TypeScript، والثانية صورة تشغيل خفيفة بلا أدوات تطوير.
# المنفذ داخل الحاوية 5000. الإعدادات تأتي من متغيرات البيئة (docker-compose → .env) لا من ملف داخل الصورة.

FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-bookworm-slim
ENV NODE_ENV=production \
    PORT=5000
WORKDIR /app
COPY package.json package-lock.json ./
# تبعيات التشغيل فقط (bcrypt يأتي بملفاته المبنية مسبقاً لـ linux x64/arm64)
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
USER node
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/src/server.js"]
