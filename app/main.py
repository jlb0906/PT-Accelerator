from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from pathlib import Path
import os
import logging
import yaml
import uvicorn

from app.services.cloudflare_speed_test import CloudflareSpeedTestService
from app.services.hosts_manager import HostsManager
from app.services.scheduler import SchedulerService
from app.services.torrent_clients import TorrentClientManager
from app.api.routes import router as api_router

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("logs/app.log")
    ]
)
logger = logging.getLogger(__name__)

# 创建必要的目录
os.makedirs("logs", exist_ok=True)
os.makedirs("config", exist_ok=True)

# 初始化配置
CONFIG_PATH = "config/config.yaml"
DEFAULT_CLOUDFLARE_IP = "104.16.91.215"
DEFAULT_CONFIG = {
    "cloudflare": {
        "enable": True,
        "cron": "0 0 * * *",  # 每天零点运行
        "ipv6": False,
        "additional_args": "",
        "notify": True
    },
    "trackers": [
        {
            "name": "示例Tracker",
            "domain": "tracker.example.com",
            "enable": True,
            "ip": DEFAULT_CLOUDFLARE_IP
        }
    ],
    "hosts_sources": [
        {
            "name": "GitHub（Gitlab源）",
            "url": "https://gitlab.com/ineo6/hosts/-/raw/master/next-hosts",
            "enable": True
        },
        {
            "name": "GitHub（Gitee源）",
            "url": "https://gitee.com/godfather1103/github-hosts/raw/master/hosts",
            "enable": True
        },
        {
            "name": "TMDB（Gitee源）",
            "url": "https://gitee.com/nirvanaalex/hosts/raw/master/hosts",
            "enable": True
        },
        {
            "name": "TMDB（GitHub源套代理）",
            "url": "https://ghfast.top/https://raw.githubusercontent.com/cnwikee/CheckTMDB/refs/heads/main/Tmdb_host_ipv4",
            "enable": True
        },
        {
            "name": "TMDB（GitHub源2套代理）",
            "url": "https://ghfast.top/https://raw.githubusercontent.com/ChenXinBest/hosts_check/refs/heads/master/hosts.txt",
            "enable": True
        },
        {
            "name": "GitHub&TMDB（GitHub源3套代理）",
            "url": "https://ghfast.top/https://raw.githubusercontent.com/kekylin/hosts/main/hosts",
            "enable": True
        }
    ]
}

# 创建nowip_hosts.txt文件，确保cfst_hosts.sh脚本能正常运行
def create_nowip_file():
    # 检查文件是否存在
    if not os.path.exists("nowip_hosts.txt"):
        try:
            with open("nowip_hosts.txt", "w") as f:
                f.write(DEFAULT_CLOUDFLARE_IP)
            logger.info(f"成功创建nowip_hosts.txt文件，内容为: {DEFAULT_CLOUDFLARE_IP}")
        except Exception as e:
            logger.error(f"创建nowip_hosts.txt文件失败: {str(e)}")
    
    # 检查CloudflareST_linux_amd64目录下是否也需要此文件
    cfst_dir = "CloudflareST_linux_amd64"
    if os.path.exists(cfst_dir) and not os.path.exists(os.path.join(cfst_dir, "nowip_hosts.txt")):
        try:
            with open(os.path.join(cfst_dir, "nowip_hosts.txt"), "w") as f:
                f.write(DEFAULT_CLOUDFLARE_IP)
            logger.info(f"成功在{cfst_dir}目录下创建nowip_hosts.txt文件")
        except Exception as e:
            logger.error(f"在{cfst_dir}目录下创建nowip_hosts.txt文件失败: {str(e)}")

# 加载或创建配置文件
def load_config():
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False, allow_unicode=True)
        return DEFAULT_CONFIG
    
    with open(CONFIG_PATH, 'r') as f:
        config = yaml.safe_load(f)
    
    # 检查配置是否完整
    if not config:
        return DEFAULT_CONFIG
    
    # 只补全顶级字段，不再补全trackers内容
    for key, value in DEFAULT_CONFIG.items():
        if key not in config:
            config[key] = value
    
    # 移除废弃的配置项
    need_save = False
    if "cloudflare" in config:
        if "ipv4" in config["cloudflare"]:
            logger.info("从配置中移除废弃的ipv4字段")
            del config["cloudflare"]["ipv4"]
            need_save = True
    
    # 如果有字段被移除，保存更新后的配置
    if need_save:
        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
    
    return config

# 创建应用
app = FastAPI(title="PT-Accelerator")

# 挂载静态文件
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

# 模板
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

# 创建nowip_hosts.txt文件
create_nowip_file()

# 服务初始化
config = load_config()
hosts_manager = HostsManager(config)
cloudflare_service = CloudflareSpeedTestService(config, hosts_manager)
scheduler_service = SchedulerService(config, cloudflare_service, hosts_manager)
torrent_client_manager = TorrentClientManager(config)

# 注册路由
app.include_router(api_router, prefix="/api")

# 主页
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        "index.html", 
        {"request": request, "config": config}
    )

# 运行时更新配置
@app.on_event("startup")
async def startup_event():
    # 启动调度器
    scheduler_service.start()
    logger.info("应用已启动，调度器已开始运行")

# 关闭时停止调度器
@app.on_event("shutdown")
async def shutdown_event():
    scheduler_service.stop()
    logger.info("应用已关闭，调度器已停止")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=23333, reload=True)