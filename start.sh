#!/bin/bash
set -e  # 遇到错误立即退出

# 日志函数
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log "PT-Accelerator 启动脚本开始运行..."

# 创建必要的目录
log "创建必要的目录..."
mkdir -p config logs
if [ ! -d "config" ] || [ ! -d "logs" ]; then
    log "错误: 无法创建必要的目录，请检查权限"
    exit 1
fi

# 检查hosts文件权限
log "检查 /etc/hosts 文件权限..."
if [ ! -w "/etc/hosts" ]; then
    log "警告: 无法写入 /etc/hosts 文件，程序可能无法正常工作"
    log "请使用 sudo 或者 root 权限运行，或者确保当前用户有写入 /etc/hosts 的权限"
fi

# 确保CloudflareST有执行权限
if [ -f "CloudflareST_linux_amd64/CloudflareST" ]; then
    log "设置 CloudflareST 可执行权限..."
    chmod +x CloudflareST_linux_amd64/CloudflareST
    chmod +x CloudflareST_linux_amd64/cfst_hosts.sh
else
    log "警告: 未找到 CloudflareST 文件，IP优选功能可能不可用"
fi

# 创建nowip_hosts.txt文件（如果不存在）
if [ ! -f "nowip_hosts.txt" ]; then
    log "创建 nowip_hosts.txt 文件..."
    echo "104.16.91.215" > nowip_hosts.txt
    
    # 检查CloudflareST_linux_amd64目录下是否也需要此文件
    if [ -d "CloudflareST_linux_amd64" ] && [ ! -f "CloudflareST_linux_amd64/nowip_hosts.txt" ]; then
        cp nowip_hosts.txt CloudflareST_linux_amd64/nowip_hosts.txt
    fi
fi

# 启动应用
log "启动应用..."
python -m uvicorn app.main:app --host 0.0.0.0 --port 23333

# 注意：此行永远不会执行，因为uvicorn会保持运行状态
log "应用已停止" 