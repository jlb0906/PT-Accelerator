#!/bin/bash

# 创建必要的目录
mkdir -p config logs
 
# 启动应用
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080 