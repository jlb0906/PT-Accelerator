# PT-Accelerator

一个面向PT站点用户的全自动加速与管理平台，集成Cloudflare IP优选、PT Tracker批量管理、GitHub/TMDB等站点加速、下载器一键导入、Web可视化配置等多种功能，支持Docker一键部署，适合所有对网络加速和PT站点体验有高要求的用户。

---

## 功能亮点

- **Cloudflare IP优选**：集成CloudflareSpeedTest，自动定时优选全球最快Cloudflare IP，极大提升PT站点和GitHub等访问速度。
- **PT Tracker批量管理**：支持批量添加、批量清空、批量导入、单个删除、状态切换等操作，Tracker管理极致高效。
- **下载器一键导入**：支持qBittorrent、Transmission等主流下载器，自动导入Tracker列表并智能筛选Cloudflare站点。
- **Hosts源多路合并**：内置多条GitHub/TMDB等Hosts源，自动合并、去重、优选，提升全局访问体验。
- **Web可视化配置**：所有操作均可在现代化Web界面完成，支持定时任务、白名单、日志、配置等全方位管理。
- **一键清空/重建**：支持一键清空所有Tracker、清空并重建hosts文件，彻底解决历史污染和遗留问题。
- **日志与状态监控**：内置系统日志、任务进度、调度器状态等实时监控，方便排查和优化。
- **极致兼容性**：支持Docker、原生Python环境，支持Linux/Windows/Mac，适配多种部署场景。

---

## 快速开始

### 1. Docker一键部署

推荐使用Docker，简单高效：

```bash
docker run -d \
  --name pt-accelerator \
  --network host \
  -v /etc/hosts:/etc/hosts \
  -v /path/to/config:/app/config \
  -v /path/to/logs:/app/logs \
  -p 23333:23333 \
  -e TZ=Asia/Shanghai \
  username/pt-accelerator:latest
```

或使用`docker-compose.yml`：

```yaml
version: '3'
services:
  pt-accelerator:
    build: .
    container_name: pt-accelerator
    restart: unless-stopped
    network_mode: host
    environment:
      - TZ=Asia/Shanghai
    volumes:
      - /etc/hosts:/etc/hosts
      - ./config:/app/config
      - ./logs:/app/logs
    ports:
      - "23333:23333"
```

### 2. 本地运行（开发/调试）

```bash
# 安装依赖
pip install -r requirements.txt

# 启动服务
bash start.sh
# 或
python -m uvicorn app.main:app --host 0.0.0.0 --port 23333
```

---

## Web界面入口

- 访问：http://your-ip:23333
- 支持多用户同时操作，所有配置实时生效

---

## 主要功能模块

### 1. 控制面板
- 查看调度器状态、定时任务、快速运行IP优选与Hosts更新
- 一键仅更新Hosts
- 一键清空Hosts并重建（彻底清理历史污染）

### 2. Tracker管理
- 批量添加、批量清空、单个删除、状态切换
- 一键导入下载器Tracker（自动筛选Cloudflare站点）
- 支持Cloudflare白名单管理
- Tracker IP一键批量更新

### 3. Hosts源管理
- 支持多条外部Hosts源，自动合并、去重、优选
- 支持添加、删除、启用/禁用Hosts源

### 4. 下载器管理
- 支持qBittorrent、Transmission等主流下载器
- 一键测试连接、保存配置、导入Tracker

### 5. 日志与监控
- 实时查看系统日志、操作日志、任务进度
- 支持刷新、自动滚动

---

## 配置文件说明（config/config.yaml）

- `cloudflare`：Cloudflare优选相关配置（定时任务、参数等）
- `cloudflare_domains`：Cloudflare白名单域名列表
- `hosts_sources`：外部Hosts源列表（支持自定义、增删、启用/禁用）
- `torrent_clients`：下载器配置（支持多种类型）
- `trackers`：PT站点Tracker列表（支持批量管理、自动导入、清空等）

**所有配置均可通过Web界面实时修改，无需手动编辑。**

---

## CloudflareSpeedTest说明

- 已内置CloudflareST二进制和测速脚本，自动调用，无需手动操作
- 相关参数和测速数据文件（ip.txt/ipv6.txt）可在`CloudflareST_linux_amd64`目录下自定义
- 参考：https://github.com/XIU2/CloudflareSpeedTest

---

## 常见问题

- **Q: 为什么要挂载/etc/hosts？**  
  A: 程序会自动优化和重写系统hosts文件，提升全局访问速度，必须有写入权限。

- **Q: 如何彻底清空tracker或hosts？**  
  A: Web界面提供"一键清空所有tracker""清空hosts并重建"按钮，安全高效。

- **Q: 支持哪些PT站点？**  
  A: 支持所有基于Cloudflare的PT站点，非Cloudflare站点会自动过滤。

- **Q: 日志和配置如何持久化？**  
  A: 建议挂载`/app/config`和`/app/logs`到本地目录，防止容器重启丢失数据。

---

## 依赖与环境

- Python 3.9+
- FastAPI、Uvicorn、APScheduler、requests、jinja2、python-hosts、transmission-rpc、dnspython等（详见requirements.txt）
- CloudflareST（已内置二进制）

---

## 参考项目

- [CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest)
- [GitHub Hosts](https://gitlab.com/ineo6/hosts)

---

## 许可证

MIT License

---

如有问题、建议或需求，欢迎在GitHub Issue区反馈！ 