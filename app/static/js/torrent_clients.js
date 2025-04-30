/**
 * 下载器管理相关功能
 */

// 初始化下载器配置界面
function initTorrentClientsUI() {
    console.log('Initializing Torrent Clients UI'); // 添加日志
    // 加载下载器配置
    loadTorrentClientsConfig();
    
    // 绑定保存按钮事件
    $("#save-clients-btn").on("click", saveTorrentClientsConfig);
    
    // 绑定测试连接按钮事件
    $("#test-qbittorrent-btn").on("click", function() {
        testClientConnection("qbittorrent");
    });
    
    $("#test-transmission-btn").on("click", function() {
        testClientConnection("transmission");
    });
    
    // 绑定导入Tracker按钮事件
    $("#btn-import-trackers").on("click", importTrackersFromClients);
}

// 加载下载器配置
function loadTorrentClientsConfig() {
    console.log('Loading Torrent Clients Config'); // 添加日志
    $.ajax({
        url: "/api/config",
        type: "GET",
        timeout: 10000, // 添加10秒超时
        success: function(response) {
            const clientsConfig = response.torrent_clients || {};
            
            // 加载qBittorrent配置
            const qbConfig = clientsConfig.qbittorrent || {};
            $("#qbittorrent-enable").prop("checked", qbConfig.enable || false);
            $("#qbittorrent-host").val(qbConfig.host || "localhost");
            $("#qbittorrent-port").val(qbConfig.port || 8080);
            $("#qbittorrent-username").val(qbConfig.username || "");
            $("#qbittorrent-password").val(qbConfig.password || "");
            $("#qbittorrent-https").prop("checked", qbConfig.use_https || false);
            
            // 加载Transmission配置
            const trConfig = clientsConfig.transmission || {};
            $("#transmission-enable").prop("checked", trConfig.enable || false);
            $("#transmission-host").val(trConfig.host || "localhost");
            $("#transmission-port").val(trConfig.port || 9091);
            $("#transmission-username").val(trConfig.username || "");
            $("#transmission-password").val(trConfig.password || "");
            $("#transmission-https").prop("checked", trConfig.use_https || false);
            $("#transmission-path").val(trConfig.path || "/transmission/rpc");
        },
        error: function(xhr, status, error) {
            console.error('Load config failed:', status, error); // 添加日志
            
            // 处理超时情况
            if (status === "timeout") {
                showToast("加载下载器配置超时，请检查网络连接", "warning", 10000);
            } else {
                showToast("加载下载器配置失败: " + error, "danger", 10000);
            }
        }
    });
}

// 保存下载器配置
function saveTorrentClientsConfig() {
    console.log('Saving Torrent Clients Config'); // 添加日志
    // 收集qBittorrent配置
    const qbittorrentConfig = {
        enable: $("#qbittorrent-enable").prop("checked"),
        host: $("#qbittorrent-host").val(),
        port: parseInt($("#qbittorrent-port").val()) || 23333,
        username: $("#qbittorrent-username").val(),
        password: $("#qbittorrent-password").val(),
        use_https: $("#qbittorrent-https").prop("checked")
    };
    
    // 收集Transmission配置
    const transmissionConfig = {
        enable: $("#transmission-enable").prop("checked"),
        host: $("#transmission-host").val(),
        port: parseInt($("#transmission-port").val()) || 9091,
        username: $("#transmission-username").val(),
        password: $("#transmission-password").val(),
        use_https: $("#transmission-https").prop("checked"),
        path: $("#transmission-path").val()
    };
    
    // 组合配置
    const clientsConfig = {
        qbittorrent: qbittorrentConfig,
        transmission: transmissionConfig
    };
    
    console.log('Collected config:', clientsConfig); // 添加日志

    // 发送保存请求
    console.log('Sending save request to /api/save-clients-config'); // 添加日志
    $.ajax({
        url: "/api/save-clients-config",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify(clientsConfig),
        timeout: 10000, // 添加10秒超时
        success: function(response) {
            if (response.success) {
                showToast(response.message, "success", 8000);
            } else {
                showToast(response.message, "danger", 10000);
            }
        },
        error: function(xhr, status, error) {
            console.error('Save config failed:', status, error); // 添加日志
            
            // 处理超时情况
            if (status === "timeout") {
                showToast("保存下载器配置超时，请检查网络连接", "warning", 10000);
            } else {
                showToast("保存下载器配置失败: " + error, "danger", 10000);
            }
        }
    });
}

// 测试下载器连接
function testClientConnection(clientType) {
    console.log(`Testing connection for ${clientType}`); // 添加日志
    let clientConfig = {};
    
    // 根据客户端类型获取配置
    if (clientType === "qbittorrent") {
        clientConfig = {
            host: $("#qbittorrent-host").val(),
            port: parseInt($("#qbittorrent-port").val()) || 23333,
            username: $("#qbittorrent-username").val(),
            password: $("#qbittorrent-password").val(),
            use_https: $("#qbittorrent-https").prop("checked")
        };
    } else if (clientType === "transmission") {
        clientConfig = {
            host: $("#transmission-host").val(),
            port: parseInt($("#transmission-port").val()) || 9091,
            username: $("#transmission-username").val(),
            password: $("#transmission-password").val(),
            use_https: $("#transmission-https").prop("checked"),
            path: $("#transmission-path").val()
        };
    }
    
    console.log(`Testing ${clientType} connection with config:`, clientConfig); // 修改日志
    
    // 直接发起请求，不再显示进度弹窗和进度条
    $.ajax({
        url: "/api/test-client-connection",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify({
            client_type: clientType,
            client_config: clientConfig
        }),
        timeout: 10000, // 添加10秒超时
        beforeSend: function() {
            console.log(`Sending ${clientType} test connection request`); // 修改日志
        },
        success: function(response) {
            if (response.success) {
                showToast(response.message, "success", 8000);
            } else {
                showToast(response.message || "连接测试失败", "danger", 10000);
            }
        },
        error: function(xhr, status, error) {
            console.error(`${clientType} test connection failed:`, status, error); // 添加日志
            // 处理超时情况
            if (status === "timeout") {
                showToast(`${clientType}连接测试超时，请检查地址和端口是否正确`, "warning", 10000);
            } else {
                showToast("测试连接失败: " + error, "danger", 10000);
            }
        }
    });
}

// 从下载器导入Tracker
function importTrackersFromClients() {
    console.log('Starting Tracker import from clients');
    
    // 显示Toast提示而不是阻塞式弹窗
    showToast("开始从下载器导入Tracker，任务将在后台执行...", "info", 8000);
    
    // 发送导入请求
    console.log('Sending import request to /api/import-trackers-from-clients');
    $.ajax({
        url: "/api/import-trackers-from-clients",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify({}),
        timeout: 30000, // 30秒超时，应该足够获取Tracker列表
        beforeSend: function() {
            console.log('Sending import Tracker request');
        },
        success: function(response) {
            console.log('Import Tracker response:', response);
            
            if (response.status === "success") {
                // 显示成功消息
                showToast(response.message, "success", 8000);
                // 刷新Tracker列表
                loadTrackers();
                
                // 如果消息中提到后台任务，提示用户稍后刷新
                if (response.message && response.message.includes("后台启动")) {
                    setTimeout(function() {
                        showToast("Hosts更新任务正在后台进行，请稍后刷新页面查看最新结果", "info", 8000);
                    }, 2000);
                    
                    // 5秒后自动刷新Tracker列表，可能此时已完成
                    setTimeout(loadTrackers, 5000);
                    // 10秒后再次刷新，以获取最终结果
                    setTimeout(loadTrackers, 10000);
                }
            } else if (response.status === "warning") {
                showToast(response.message, "warning", 8000);
            } else {
                showToast(response.message || "导入失败", "danger", 10000);
            }
        },
        error: function(xhr, status, error) {
            console.error('Import Tracker failed:', status, error);
            
            if (status === "timeout") {
                // 超时但不一定失败，可能只是处理耗时
                showToast("导入Tracker处理时间超过60秒，如果导入tracker数量较多，任务可能仍在后端处理。请稍后查看Tracker列表或日志", "warning", 10000);
                // 5秒后尝试刷新Tracker列表
                setTimeout(loadTrackers, 5000);
            } else {
                showToast("从下载器导入Tracker失败: " + error, "danger", 10000);
            }
        }
    });
}

// 页面加载完成后执行
document.addEventListener('DOMContentLoaded', function() {
    // 检查是否在下载器管理页面
    if (document.getElementById('torrent-clients-form')) {
        console.log('Torrent Clients page loaded, initializing UI'); // 添加日志
        initTorrentClientsUI();
    }
});