# 全局变量文件，用于存储服务实例，避免循环导入

# 服务实例
hosts_manager = None
cloudflare_service = None
scheduler_service = None
torrent_client_manager = None
config = None

def init_services(hm, cs, ss, tcm, cfg):
    """初始化全局服务实例"""
    global hosts_manager, cloudflare_service, scheduler_service, torrent_client_manager, config
    hosts_manager = hm
    cloudflare_service = cs
    scheduler_service = ss
    torrent_client_manager = tcm
    config = cfg

def get_hosts_manager():
    return hosts_manager

def get_cloudflare_service():
    return cloudflare_service

def get_scheduler_service():
    return scheduler_service

def get_torrent_client_manager():
    return torrent_client_manager

def get_config():
    return config 