FROM python:3.9-slim

WORKDIR /app

# 安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制CloudflareSpeedTest
COPY CloudflareST_linux_arm64/CloudflareST /usr/local/bin/
RUN chmod +x /usr/local/bin/CloudflareST

# 复制应用代码
COPY . .

# 创建配置目录
RUN mkdir -p /app/config /app/logs

# 暴露端口
ARG APP_PORT=23333
ENV APP_PORT=${APP_PORT}
EXPOSE ${APP_PORT}

# 启动应用
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${APP_PORT}"]