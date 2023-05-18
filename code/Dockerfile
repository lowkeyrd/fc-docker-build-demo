# 基于node:alpine镜像
FROM node:alpine

# 设置工作目录
WORKDIR /app

# 复制package.json和package-lock.json到容器中
COPY package*.json ./

# 安装依赖
RUN npm install

# 将所有文件复制到容器中
COPY . .

# 构建生产环境代码
RUN npm run build

# 使用nginx来提供静态资源服务
FROM nginx:alpine
COPY --from=0 /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]