from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request, status, Query
from fastapi.responses import JSONResponse
import yaml
import os
import logging
from typing import List, Dict, Any
from pydantic import BaseModel
import re
from croniter import croniter
from urllib.parse import urlparse

from app.services.cloudflare_speed_test import CloudflareSpeedTestService
from app.services.hosts_manager import HostsManager
from app.services.scheduler import SchedulerService
from app.services.torrent_clients import TorrentClientManager
from app.models import Tracker, HostsSource, CloudflareConfig, TorrentClientConfig, BatchAddDomainsRequest

# 配置相关常量
CONFIG_PATH = "config/config.yaml"
DEFAULT_CLOUDFLARE_IP = "104.16.91.215"  # 全局默认Cloudflare IP

# 获取日志记录器
logger = logging.getLogger(__name__)

router = APIRouter()

# 获取服务实例的依赖函数
def get_hosts_manager():
    from app.main import hosts_manager
    return hosts_manager

def get_cloudflare_service():
    from app.main import cloudflare_service
    return cloudflare_service

def get_scheduler_service():
    from app.main import scheduler_service
    return scheduler_service

def get_torrent_client_manager():
    from app.main import torrent_client_manager
    return torrent_client_manager

def get_config():
    from app.main import config
    return config

# 获取配置
@router.get("/config")
async def get_config_api():
    """获取当前配置"""
    config = get_config()
    return config

# 更新配置（CRON表达式校验）
@router.post("/config")
async def update_config(
    config_data: Dict[str, Any],
    hosts_manager: HostsManager = Depends(get_hosts_manager),
    cloudflare_service: CloudflareSpeedTestService = Depends(get_cloudflare_service),
    scheduler_service: SchedulerService = Depends(get_scheduler_service)
):
    """更新配置"""
    try:
        # CRON表达式校验
        cron_expr = config_data.get("cloudflare", {}).get("cron", "0 0 * * *")
        if not croniter.is_valid(cron_expr):
            raise HTTPException(status_code=400, detail="CRON表达式无效，请检查格式")
        
        # 保存配置
        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(config_data, f, default_flow_style=False, allow_unicode=True)
        
        # 更新服务配置
        hosts_manager.update_config(config_data)
        cloudflare_service.update_config(config_data)
        
        # 重启调度器
        scheduler_service.stop()
        scheduler_service.update_config(config_data)
        scheduler_service.start()
        
        return {"message": "配置已更新"}
    except Exception as e:
        logger.error(f"更新配置失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"更新配置失败: {str(e)}")

# 手动运行CloudflareSpeedTest
@router.post("/run-cloudflare-test")
async def run_cloudflare_test(
    background_tasks: BackgroundTasks,
    hosts_manager: HostsManager = Depends(get_hosts_manager)
):
    """手动运行CloudflareSpeedTest和更新hosts源（严格串行）"""
    try:
        # 创建组合任务
        def combined_task():
            logger.info("手动执行组合任务：优选IP + 更新tracker + 更新hosts（严格串行）")
            hosts_manager.run_cfst_and_update_hosts()
        # 在后台运行，避免阻塞API响应
        background_tasks.add_task(combined_task)
        return {"message": "IP优选与Hosts更新任务已启动（严格串行）"}
    except Exception as e:
        logger.error(f"启动组合任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"启动组合任务失败: {str(e)}")

# 获取调度器状态
@router.get("/scheduler-status")
async def get_scheduler_status(
    scheduler_service: SchedulerService = Depends(get_scheduler_service)
):
    """获取调度器状态"""
    return {
        "running": scheduler_service.is_running(),
        "jobs": scheduler_service.get_jobs()
    }

# 兼容旧版前端，避免404错误
@router.get("/last-result")
async def get_last_result_compatibility():
    """兼容旧版前端，返回空结果"""
    return {
        "success": False,
        "message": "此API端点已弃用，优选结果不再显示",
        "time": "",
        "results": []
    }

# 任务状态API
@router.get("/task-status")
async def get_task_status(
    hosts_manager: HostsManager = Depends(get_hosts_manager),
    scheduler_service: SchedulerService = Depends(get_scheduler_service)
):
    """获取当前任务状态
    
    前端轮询此接口以获取后台任务的执行状态
    
    Returns:
        任务状态：
        - status: done | running
        - message: 任务状态描述
    """
    try:
        # 首先检查scheduler_service中的任务状态
        scheduler_status = getattr(scheduler_service, 'get_task_status', lambda: {"status": "done", "message": "无任务"})()
        if scheduler_status.get("status") == "running":
            return scheduler_status
            
        # 然后检查hosts_manager中的任务状态
        hosts_status = hosts_manager.get_task_status()
        if hosts_status.get("status") == "running":
            return hosts_status
            
        # 如果都没有运行中的任务，返回默认完成状态
        return {
            "status": "done",
            "message": "无正在运行的任务"
        }
    except Exception as e:
        logger.error(f"获取任务状态时出错: {str(e)}", exc_info=True)
        # 返回安全的默认状态
        return {
            "status": "done",
            "message": "获取任务状态出错，请检查日志"
        }

# 获取日志
@router.get("/logs")
async def get_logs(lines: int = 1000):
    """获取最近的日志，返回带换行的字符串，便于前端显示"""
    try:
        log_file = "logs/app.log"
        if not os.path.exists(log_file):
            return {"logs": ""}
        with open(log_file, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return {"logs": ""}
            chunk_size = 4096
            pos = max(0, size - chunk_size * 10)
            f.seek(pos)
            content = f.read().decode('utf-8', errors='replace')
            logs = content.splitlines()
            while len(logs) < lines and pos > 0:
                pos = max(0, pos - chunk_size)
                f.seek(pos)
                content = f.read(chunk_size).decode('utf-8', errors='replace')
                logs = content.splitlines() + logs
            # 返回带换行的字符串
            return {"logs": "\n".join(logs[-lines:])}
    except Exception as e:
        logger.error(f"获取日志失败: {str(e)}")
        try:
            with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                logs = f.readlines()
                return {"logs": "".join(logs[-lines:])}
        except Exception as e2:
            logger.error(f"备用方式读取日志也失败: {str(e2)}")
            return {"logs": "日志读取失败，请检查日志文件权限和编码"}

# ===== Cloudflare白名单管理API =====

@router.get("/cloudflare-domains")
async def get_cloudflare_domains():
    config = get_config()
    domains = config.get("cloudflare_domains", [])
    return {"cloudflare_domains": domains}

@router.post("/cloudflare-domains")
async def add_cloudflare_domain(domain: str = Query(..., description="要添加的Cloudflare域名")):
    config = get_config()
    domains = set(config.get("cloudflare_domains", []))
    domains.add(domain.strip().lower())
    config["cloudflare_domains"] = list(domains)
    with open(CONFIG_PATH, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
    hosts_manager = get_hosts_manager()
    hosts_manager.update_config(config)
    try:
        import app.main
        app.main.config = config
    except Exception:
        pass
    # 新增：白名单变更后自动更新hosts
    hosts_manager.update_hosts()
    return {"message": f"已添加 {domain} 到Cloudflare白名单", "cloudflare_domains": list(domains)}

@router.delete("/cloudflare-domains")
async def delete_cloudflare_domain(domain: str = Query(..., description="要删除的Cloudflare域名")):
    config = get_config()
    domains = set(config.get("cloudflare_domains", []))
    domains.discard(domain.strip().lower())
    config["cloudflare_domains"] = list(domains)
    with open(CONFIG_PATH, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
    hosts_manager = get_hosts_manager()
    hosts_manager.update_config(config)
    try:
        import app.main
        app.main.config = config
    except Exception:
        pass
    # 新增：白名单变更后自动更新hosts
    hosts_manager.update_hosts()
    return {"message": f"已从Cloudflare白名单移除 {domain}", "cloudflare_domains": list(domains)}

# 修改添加tracker接口，支持force_cloudflare参数
@router.post("/trackers")
async def add_tracker(
    tracker: dict,
    background_tasks: BackgroundTasks,
    hosts_manager: HostsManager = Depends(get_hosts_manager),
    force_cloudflare: bool = False
):
    try:
        domain = tracker.get("domain", "")
        if domain:
            domain = re.sub(r"^https?://", "", domain, flags=re.IGNORECASE)
            domain = domain.split("/")[0]
            tracker["domain"] = domain
        config = get_config()
        if "trackers" not in config:
            config["trackers"] = []
        for existing in config["trackers"]:
            if existing["domain"] == tracker["domain"]:
                raise HTTPException(status_code=400, detail="Tracker已存在")
        ip_set = set()
        for t in config["trackers"]:
            if t.get("enable") and t.get("ip"):
                ip_set.add(t["ip"])
        if len(ip_set) > 1:
            raise HTTPException(status_code=400, detail="检测到现有Tracker的IP不一致，请先统一所有Tracker的IP后再添加。")
        elif len(ip_set) == 1:
            default_ip = list(ip_set)[0]
        else:
            default_ip = hosts_manager.best_cloudflare_ip or "104.16.91.215"
        tracker["ip"] = default_ip
        config["trackers"].append(tracker)
        # 新增：如force_cloudflare为True，自动写入白名单
        if force_cloudflare:
            domains = set(config.get("cloudflare_domains", []))
            domains.add(domain.strip().lower())
            config["cloudflare_domains"] = list(domains)
        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        hosts_manager.update_config(config)
        # 新增：如force_cloudflare为True，自动更新hosts，确保白名单和tracker同步生效
        if force_cloudflare:
            hosts_manager.update_hosts()
        else:
            background_tasks.add_task(hosts_manager.update_hosts)
        try:
            import app.main
            app.main.config = config
        except Exception:
            pass
        return {"message": "Tracker已添加，Hosts更新任务已在后台启动"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"添加Tracker失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"添加Tracker失败: {str(e)}")

@router.delete("/trackers/{domain}")
async def delete_tracker(
    domain: str,
    background_tasks: BackgroundTasks,
    hosts_manager: HostsManager = Depends(get_hosts_manager)
):
    """删除Tracker"""
    try:
        # 更新配置
        config = get_config()
        if "trackers" not in config:
            raise HTTPException(status_code=404, detail="Tracker不存在")
        
        found = False
        config["trackers"] = [t for t in config["trackers"] if t["domain"] != domain]
        # 新增：同步清理历史
        hosts_manager.remove_tracker_domain(domain)
        
        # 保存配置
        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        
        # 更新hosts_manager的配置
        hosts_manager.update_config(config)
        
        # 同步更新全局config对象，确保前端API获取到最新数据
        try:
            import app.main
            app.main.config = config
            logger.info(f"删除Tracker API已同步刷新全局config对象，确保前端获取到最新数据")
        except Exception as e:
            logger.error(f"删除Tracker API刷新全局config对象失败: {str(e)}")
        
        # 在后台更新hosts
        background_tasks.add_task(hosts_manager.update_hosts)
        
        return {"message": "Tracker已删除，Hosts更新任务已在后台启动"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"删除Tracker失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"删除Tracker失败: {str(e)}")

# 添加hosts源（URL校验）
@router.post("/hosts-sources")
async def add_hosts_source(
    source: Dict[str, Any],
    background_tasks: BackgroundTasks,  # 新增参数
    hosts_manager: HostsManager = Depends(get_hosts_manager)
):
    """添加hosts源"""
    try:
        # URL校验和自动补全
        url = source.get("url", "")
        if url and not re.match(r"^https?://", url, re.IGNORECASE):
            url = "https://" + url
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise HTTPException(status_code=400, detail="Hosts源URL无效，请检查格式")
        source["url"] = url
        config = get_config()
        if "hosts_sources" not in config:
            config["hosts_sources"] = []
        for existing in config["hosts_sources"]:
            if existing["url"] == source["url"]:
                raise HTTPException(status_code=400, detail="hosts源已存在")
        config["hosts_sources"].append(source)
        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        
        # 更新hosts_manager的配置
        hosts_manager.update_config(config)
        
        # 同步更新全局config对象，确保前端API获取到最新数据
        try:
            import app.main
            app.main.config = config
            logger.info("添加hosts源API已同步刷新全局config对象，确保前端获取到最新数据")
        except Exception as e:
            logger.error(f"添加hosts源API刷新全局config对象失败: {str(e)}")
            
        # 异步更新hosts
        background_tasks.add_task(hosts_manager.update_hosts)
        return {"message": "hosts源已添加，正在后台更新hosts"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"添加hosts源失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"添加hosts源失败: {str(e)}")

@router.delete("/hosts-sources")
async def delete_hosts_source(
    url: str,
    background_tasks: BackgroundTasks,  # 新增参数
    hosts_manager: HostsManager = Depends(get_hosts_manager)
):
    """删除hosts源"""
    try:
        config = get_config()
        if "hosts_sources" not in config:
            raise HTTPException(status_code=404, detail="hosts源不存在")
        config["hosts_sources"] = [s for s in config["hosts_sources"] if s["url"] != url]
        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
            
        # 更新hosts_manager的配置
        hosts_manager.update_config(config)
        
        # 同步更新全局config对象，确保前端API获取到最新数据
        try:
            import app.main
            app.main.config = config
            logger.info("删除hosts源API已同步刷新全局config对象，确保前端获取到最新数据")
        except Exception as e:
            logger.error(f"删除hosts源API刷新全局config对象失败: {str(e)}")
            
        # 异步更新hosts
        background_tasks.add_task(hosts_manager.update_hosts)
        return {"message": "hosts源已删除，正在后台更新hosts"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"删除hosts源失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"删除hosts源失败: {str(e)}")

# 手动更新hosts
@router.post("/update-hosts")
async def update_hosts(
    background_tasks: BackgroundTasks,
    hosts_manager: HostsManager = Depends(get_hosts_manager)
):
    """手动更新hosts"""
    try:
        # 在后台运行，避免阻塞API响应
        background_tasks.add_task(hosts_manager.update_hosts)
        return {"message": "hosts更新任务已启动"}
    except Exception as e:
        logger.error(f"更新hosts失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"更新hosts失败: {str(e)}")

# 获取当前hosts
@router.get("/current-hosts")
async def get_current_hosts(
    hosts_manager: HostsManager = Depends(get_hosts_manager)
):
    """获取当前hosts"""
    try:
        return {"hosts": hosts_manager.read_system_hosts()}
    except Exception as e:
        logger.error(f"获取hosts失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"获取hosts失败: {str(e)}")

# ===== 添加新的模型和API端点 =====

class DomainList(BaseModel):
    domains: List[str]

# 批量添加PT站点域名
@router.post("/batch-add-domains")
async def batch_add_domains(
    request: Request,
    background_tasks: BackgroundTasks,
    hosts_manager: HostsManager = Depends(get_hosts_manager)
):
    """批量添加域名"""
    try:
        # 获取请求数据
        data = await request.json()
        domains_data = data.get("domains", "")
        
        # 处理不同类型的输入
        if isinstance(domains_data, list):
            domains = domains_data
        else:
            # 假设是字符串，按行分割
            domains = domains_data.strip().split("\n")
        
        # 过滤空行
        domains = [domain.strip() for domain in domains if domain and domain.strip()]
        
        # 新增：自动清洗tracker域名
        cleaned_domains = []
        for domain in domains:
            d = re.sub(r"^https?://", "", domain, flags=re.IGNORECASE)
            d = d.split("/")[0]
            cleaned_domains.append(d)
        domains = cleaned_domains
        
        if not domains:
            return {"status": "warning", "message": "没有提供有效的域名"}
        
        # 读取当前配置
        config = get_config()
        if "trackers" not in config:
            config["trackers"] = []
            
        # 检查所有tracker的IP是否一致
        ip_set = set()
        for t in config["trackers"]:
            if t.get("enable") and t.get("ip"):
                ip_set.add(t["ip"])
                
        if len(ip_set) > 1:
            return {"status": "error", "message": "检测到现有Tracker的IP不一致，请先统一所有Tracker的IP后再添加。"}
        
        # 获取默认IP
        if len(ip_set) == 1:
            default_ip = list(ip_set)[0]
        else:
            # 没有tracker时，使用优选IP或默认IP
            default_ip = hosts_manager.best_cloudflare_ip or "104.16.91.215"
            
        # 处理结果统计
        added = []
        skipped = []
        
        # 批量添加域名
        for domain in domains:
            # 检查是否已存在
            if any(t["domain"] == domain for t in config["trackers"]):
                skipped.append(domain)
                continue
                
            # 添加新tracker
            config["trackers"].append({
                "name": domain,
                "domain": domain,
                "ip": default_ip,
                "enable": True
            })
            added.append(domain)
            
        # 保存配置
        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
            
        # 更新hosts_manager的配置
        hosts_manager.update_config(config)
        
        # 同步更新全局config对象，确保前端API获取到最新数据
        try:
            import app.main
            app.main.config = config
            logger.info("批量添加域名API已同步刷新全局config对象，确保前端获取到最新数据")
        except Exception as e:
            logger.error(f"批量添加域名API刷新全局config对象失败: {str(e)}")
            
        # 后台更新hosts
        background_tasks.add_task(hosts_manager.update_hosts)
        
        # 构建响应消息
        message = f"批量添加完成：成功添加 {len(added)} 个域名，跳过 {len(skipped)} 个已存在的域名"
        details = {
            "added": added,
            "skipped": skipped
        }
        
        return {
            "status": "success", 
            "message": message,
            "details": details
        }
    except Exception as e:
        logger.error(f"批量添加域名失败: {str(e)}")
        return {"status": "error", "message": f"批量添加域名失败: {str(e)}"}

# 运行CloudflareSpeedTest优选脚本
@router.post("/run-cfst-script")
async def run_cfst_script(
    background_tasks: BackgroundTasks,
    hosts_manager: HostsManager = Depends(get_hosts_manager)
):
    """运行CloudflareSpeedTest优选脚本和更新hosts源（严格串行）"""
    try:
        def combined_task():
            logger.info("严格串行执行：优选IP+更新tracker+更新hosts")
            hosts_manager.run_cfst_and_update_hosts()
        background_tasks.add_task(combined_task)
        return {"message": "IP优选与Hosts更新任务已启动（严格串行）"}
    except Exception as e:
        logger.error(f"启动组合任务失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"启动组合任务失败: {str(e)}")

# 手动更新所有Tracker为最佳IP
@router.post("/update-all-trackers")
async def update_all_trackers(
    ip: str,
    hosts_manager: HostsManager = Depends(get_hosts_manager)
):
    """手动更新所有Tracker为指定IP"""
    try:
        hosts_manager._update_all_trackers_ip(ip)
        hosts_manager.update_hosts()
        
        # 确保全局config对象同步更新
        try:
            import app.main
            app.main.config = hosts_manager.config
            logger.info("API端点已同步刷新全局config对象，确保前端获取到最新数据")
        except Exception as e:
            logger.error(f"API端点刷新全局config对象失败: {str(e)}")
            
        return {"message": f"已将所有Tracker的IP更新为 {ip}"}
    except Exception as e:
        logger.error(f"更新所有Tracker的IP失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"更新所有Tracker的IP失败: {str(e)}")

# ===== 下载器相关API =====

# 测试下载器连接
@router.post("/test-client-connection")
async def test_client_connection(
    request: Request,
    torrent_client_manager: TorrentClientManager = Depends(get_torrent_client_manager)
):
    # 从请求体中获取参数
    data = await request.json()
    client_type = data.get("client_type")
    client_config = data.get("client_config", {})
    
    logger.info(f"测试下载器连接: {client_type}, 配置: {client_config}")
    
    if not client_type:
        logger.error("测试下载器连接失败: 缺少client_type参数")
        return {"success": False, "message": "缺少client_type参数"}
    """测试下载器连接"""
    try:
        # 创建临时客户端进行测试
        if client_type == "qbittorrent":
            from app.services.torrent_clients import QBittorrentClient
            client = QBittorrentClient(
                host=client_config.get("host", "localhost"),
                port=client_config.get("port", 8080),
                username=client_config.get("username", ""),
                password=client_config.get("password", ""),
                use_https=client_config.get("use_https", False)
            )
        elif client_type == "transmission":
            from app.services.torrent_clients import TransmissionClient
            client = TransmissionClient(
                host=client_config.get("host", "localhost"),
                port=client_config.get("port", 9091),
                username=client_config.get("username", ""),
                password=client_config.get("password", ""),
                use_https=client_config.get("use_https", False),
                path=client_config.get("path", "/transmission/rpc")
            )
        else:
            return {"success": False, "message": f"不支持的下载器类型: {client_type}"}
        
        # 测试连接
        result = client.test_connection()
        return result
    except Exception as e:
        logger.error(f"测试下载器连接失败: {str(e)}")
        return {"success": False, "message": f"测试连接失败: {str(e)}"}

# 保存下载器配置（主机和端口校验）
@router.post("/save-clients-config")
async def save_clients_config_route(
    clients_config: dict,
    config: Dict[str, Any] = Depends(get_config)  # 使用依赖函数获取配置
):
    logger.info("Received request to save torrent clients config") # 添加日志
    try:
        # 主机和端口校验
        for client_type, client in clients_config.items():
            host = client.get("host", "")
            port = client.get("port", 0)
            # 主机校验（IP或域名）
            if not re.match(r"^(?:[a-zA-Z0-9\-\.]+|\d{1,3}(?:\.\d{1,3}){3})$", host):
                raise HTTPException(status_code=400, detail=f"{client_type}主机地址无效")
            # 端口校验
            try:
                port = int(port)
            except Exception:
                raise HTTPException(status_code=400, detail=f"{client_type}端口必须为数字")
            if not (1 <= port <= 65535):
                raise HTTPException(status_code=400, detail=f"{client_type}端口范围无效(1-65535)")
        # 更新配置中的 torrent_clients 部分
        config['torrent_clients'] = clients_config
        
        # 保存更新后的配置
        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        
        logger.info("Torrent clients config saved successfully") # 添加日志
        # 更新 TorrentClientManager 中的配置
        torrent_client_manager = get_torrent_client_manager()
        torrent_client_manager.update_config(config)
        
        return {"success": True, "message": "下载器配置已保存"}
    except Exception as e:
        logger.error(f"Error saving torrent clients config: {str(e)}", exc_info=True) # 添加日志和异常信息
        return {"success": False, "message": f"保存下载器配置失败: {str(e)}"}

# 测试下载器连接
@router.post("/test-client-connection")
async def test_client_connection_route(data: dict):
    client_type = data.get("client_type")
    client_config = data.get("client_config")
    logger.info(f"Received request to test {client_type} connection") # 添加日志
    logger.debug(f"Client config for testing: {client_config}") # 添加详细配置日志
    
    if not client_type or not client_config:
        logger.warning("Missing client_type or client_config in test request") # 添加日志
        return {"success": False, "message": "请求参数不完整"}
    
    try:
        success, message = await torrent_client_manager.test_connection(client_type, client_config)
        logger.info(f"Test connection result for {client_type}: success={success}, message='{message}'") # 添加日志
        return {"success": success, "message": message}
    except Exception as e:
        logger.error(f"Error testing {client_type} connection: {str(e)}", exc_info=True) # 添加日志和异常信息
        return {"success": False, "message": f"测试连接时发生错误: {str(e)}"}

# 从下载器导入Tracker
@router.post("/import-trackers-from-clients")
async def import_trackers_from_clients_route(
    background_tasks: BackgroundTasks,
    hosts_manager: HostsManager = Depends(get_hosts_manager),
    config: Dict[str, Any] = Depends(get_config)
):
    logger.info("Received request to import trackers from clients")
    try:
        torrent_client_manager = get_torrent_client_manager()
        result = torrent_client_manager.import_trackers_from_clients()
        logger.info(f"Import trackers result: {result}")
        
        if result.get("status") == "success" and result.get("added_domains"):
            existing_domains = {tracker['domain'] for tracker in config.get('trackers', [])}
            new_trackers_added = False
            cf_domains = []
            non_cf_domains = []
            
            # 临时调整日志级别为DEBUG，以便查看详细的Cloudflare检测日志
            hosts_manager_logger = logging.getLogger('app.services.hosts_manager')
            original_level = hosts_manager_logger.level
            hosts_manager_logger.setLevel(logging.DEBUG)
            
            # 域名清洗和Cloudflare检测
            for domain in result["added_domains"]:
                # 清洗tracker域名，移除http前缀和路径
                d = re.sub(r"^https?://", "", domain, flags=re.IGNORECASE)
                d = d.split("/")[0]
                domain = d
                
                # 提取纯域名（移除端口号）用于Cloudflare检测
                clean_domain = domain.split(':')[0] if ':' in domain else domain
                
                logger.info(f"[Cloudflare检测] 正在检测下载器导入的域名: {clean_domain}")
                # 检测Cloudflare
                if hosts_manager.is_cloudflare_domain(clean_domain):
                    cf_domains.append(domain)
                    if domain not in existing_domains:
                        default_ip = config.get('cloudflare', {}).get('ip') or DEFAULT_CLOUDFLARE_IP
                        new_tracker = {
                            "name": domain,
                            "domain": domain,
                            "enable": True,
                            "ip": default_ip
                        }
                        config.setdefault('trackers', []).append(new_tracker)
                        existing_domains.add(domain)
                        new_trackers_added = True
                else:
                    logger.info(f"[Cloudflare检测] 域名 {clean_domain} 不是Cloudflare域名，已跳过")
                    non_cf_domains.append(domain)
            
            # 恢复原有日志级别
            hosts_manager_logger.setLevel(original_level)
            
            # 统一输出检测结果
            if cf_domains:
                logger.info("=== Cloudflare站点检测结果 ===")
                logger.info(f"成功检测到 {len(cf_domains)} 个Cloudflare站点:")
                for domain in cf_domains:
                    logger.info(f"- {domain}")
            
            if non_cf_domains:
                logger.info(f"检测到 {len(non_cf_domains)} 个非Cloudflare站点:")
                for domain in non_cf_domains:
                    logger.info(f"- {domain}")
            
            # 只有有新的Cloudflare站点时才更新配置文件
            if new_trackers_added:
                with open(CONFIG_PATH, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
                logger.info("Updated config.yaml with imported trackers")
                hosts_manager.update_config(config)
                try:
                    import app.main
                    app.main.config = config
                    logger.info("同步刷新全局config对象，确保前端获取到最新tracker列表")
                except Exception as e:
                    logger.error(f"刷新全局config对象失败: {str(e)}")
                
                # 触发hosts更新
                background_tasks.add_task(hosts_manager.update_hosts)
                
                # 更新结果消息，区分加速和过滤站点
                total_count = len(cf_domains) + len(non_cf_domains)
                cf_only_message = f"成功导入 {len(cf_domains)} 个Cloudflare站点"
                if non_cf_domains:
                    cf_only_message += f"，已过滤 {len(non_cf_domains)} 个非Cloudflare站点"
                result["message"] = cf_only_message + "，Hosts更新任务已在后台启动"
            else:
                # 无新Cloudflare站点时的消息
                if cf_domains:
                    result["message"] = f"未发现新的Cloudflare站点，已有站点 {len(cf_domains)} 个，过滤非Cloudflare站点 {len(non_cf_domains)} 个"
                else:
                    result["message"] = f"未找到任何Cloudflare站点，已过滤非Cloudflare站点 {len(non_cf_domains)} 个"
        
        return result
    except Exception as e:
        logger.error(f"Error importing trackers from clients: {str(e)}", exc_info=True)
        return {"status": "error", "message": f"导入过程中发生错误: {str(e)}"}

@router.post("/clear-and-update-hosts")
async def clear_and_update_hosts(
    background_tasks: BackgroundTasks,
    hosts_manager: HostsManager = Depends(get_hosts_manager)
):
    """清空系统hosts文件并重新生成hosts内容"""
    try:
        # 1. 清空hosts文件内容
        hosts_path = hosts_manager._get_hosts_path()
        with open(hosts_path, 'w') as f:
            f.write('')
        # 2. 后台更新hosts
        background_tasks.add_task(hosts_manager.update_hosts)
        return {"message": "已清空hosts文件并启动更新任务"}
    except Exception as e:
        logger.error(f"清空并更新hosts失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"清空并更新hosts失败: {str(e)}")

@router.post("/clear-all-trackers")
async def clear_all_trackers(
    background_tasks: BackgroundTasks,
    hosts_manager: HostsManager = Depends(get_hosts_manager)
):
    """清空所有tracker并同步更新hosts"""
    try:
        config = get_config()
        config["trackers"] = []
        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True)
        hosts_manager.update_config(config)
        try:
            import app.main
            app.main.config = config
        except Exception:
            pass
        background_tasks.add_task(hosts_manager.update_hosts)
        return {"message": "已清空所有tracker并同步更新hosts"}
    except Exception as e:
        logger.error(f"清空所有tracker失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"清空所有tracker失败: {str(e)}")

# ... existing code ...