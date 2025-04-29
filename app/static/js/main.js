document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM fully loaded and parsed');
    // 加载初始数据
    loadDashboard();
    loadCloudflareConfig();
    loadTrackers();
    loadHostsSources();
    loadLogs();
    loadCurrentHosts();
    // 绑定事件
    bindEvents();
    enhanceInputValidation();
});

function bindEvents() {
    // 下载器管理初始化（安全调用）
    if (typeof initTorrentClientsUI === 'function') {
        try {
            console.log('初始化下载器管理界面');
            initTorrentClientsUI();
        } catch(e) {
            console.warn('initTorrentClientsUI 执行异常:', e);
        }
    } else {
        console.log('未定义initTorrentClientsUI，跳过下载器管理初始化');
    }
    // 运行CloudflareSpeedTest按钮事件
    const btnRunCloudflare = document.getElementById('btn-run-cloudflare');
    if (btnRunCloudflare) {
        btnRunCloudflare.addEventListener('click', function() {
            this.disabled = true;
            const spinner = document.createElement('div');
            spinner.className = 'spinner-container';
            spinner.innerHTML = '<div class="spinner-border spinner-border-sm text-light" role="status"><span class="visually-hidden">Loading...</span></div>';
            this.appendChild(spinner);
            fetch('/api/run-cfst-script', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    showActionResult(data.message, 'success');
                    loadCurrentHosts();
                    setTimeout(() => {
                        fetch('/api/task-status')
                            .then(res => res.json())
                            .then(res => {
                                if (res.status === 'done') {
                                    loadCurrentHosts();
                                    showToast('Hosts已自动更新', 'success');
                                }
                            });
                    }, 3000);
                })
                .catch(error => {
                    console.error('运行IP优选与Hosts更新任务失败:', error);
                    showActionResult('运行IP优选与Hosts更新任务失败', 'danger');
                })
                .finally(() => {
                    this.disabled = false;
                    this.removeChild(spinner);
                });
        });
    }
    // 更新Hosts
    const btnUpdateHosts = document.getElementById('btn-update-hosts');
    if (btnUpdateHosts) {
        btnUpdateHosts.addEventListener('click', function() {
            const resultElement = document.getElementById('action-result');
            resultElement.innerHTML = '<div class="alert alert-info">正在更新Hosts...</div>';
            fetch('/api/update-hosts', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    resultElement.innerHTML = `<div class="alert alert-success">${data.message}</div>`;
                    loadCurrentHosts();
                    setTimeout(() => { resultElement.innerHTML = ''; }, 5000);
                })
                .catch(error => {
                    console.error('更新Hosts失败:', error);
                    resultElement.innerHTML = '<div class="alert alert-danger">更新Hosts失败</div>';
                });
        });
    }
    // 保存Cloudflare配置
    const cloudflareForm = document.getElementById('cloudflare-form');
    if (cloudflareForm) {
        cloudflareForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const saveBtn = document.getElementById('save-cloudflare-btn');
            const spinner = document.getElementById('cloudflare-spinner');
            const resultSpan = document.getElementById('cloudflare-save-result');
            if (saveBtn) saveBtn.disabled = true;
            if (spinner) spinner.classList.remove('d-none');
            if (resultSpan) resultSpan.textContent = '';
            const config = {
                cloudflare: {
                    enable: document.getElementById('cloudflare-enable').checked,
                    cron: document.getElementById('cloudflare-cron').value
                }
            };
            fetch('/api/config')
                .then(response => response.json())
                .then(fullConfig => {
                    const updatedConfig = { ...fullConfig, cloudflare: config.cloudflare };
                    return fetch('/api/config', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(updatedConfig)
                    });
                })
                .then(response => response.json())
                .then(data => {
                    showToast('定时任务配置已保存', 'success');
                    if (resultSpan) {
                        resultSpan.textContent = '保存成功';
                        resultSpan.className = 'ms-2 text-success';
                        setTimeout(() => { resultSpan.textContent = ''; }, 3000);
                    }
                    loadDashboard();
                })
                .catch(error => {
                    console.error('保存配置失败:', error);
                    showToast('保存定时任务配置失败: ' + error.message, 'danger');
                    if (resultSpan) {
                        resultSpan.textContent = '保存失败';
                        resultSpan.className = 'ms-2 text-danger';
                    }
                })
                .finally(() => {
                    if (saveBtn) saveBtn.disabled = false;
                    if (spinner) spinner.classList.add('d-none');
                });
        });
    }
    // 添加Tracker
    const saveTrackerBtn = document.getElementById('save-tracker');
    if (saveTrackerBtn) {
        saveTrackerBtn.addEventListener('click', function() {
            const name = document.getElementById('tracker-name').value;
            const domain = document.getElementById('tracker-domain').value;
            const enable = document.getElementById('tracker-enable').checked;
            const forceCloudflare = document.getElementById('tracker-force-cloudflare') ? document.getElementById('tracker-force-cloudflare').checked : false;
            if (!name || !domain) {
                showToast('请填写完整信息', 'warning', 8000);
                return;
            }
            const tracker = { name, domain, enable, ip: '' };
            this.disabled = true;
            const originalText = this.textContent;
            this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> 处理中...';
            showToast('正在添加Tracker，请稍候...', 'info', 8000);
            fetch(`/api/trackers?force_cloudflare=${forceCloudflare}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(tracker)
            })
                .then(response => response.json())
                .then(data => {
                    const modal = bootstrap.Modal.getInstance(document.getElementById('addTrackerModal'));
                    if (modal) modal.hide();
                    document.getElementById('add-tracker-form').reset();
                    loadTrackers();
                    showToast(data.message || 'Tracker已添加', 'success');
                })
                .catch(error => {
                    console.error('添加Tracker失败:', error);
                    showToast(error.message, 'danger', 10000);
                })
                .finally(() => {
                    this.disabled = false;
                    this.innerHTML = originalText;
                });
        });
    }
    // 添加Hosts源
    const saveHostsSourceBtn = document.getElementById('save-hosts-source');
    if (saveHostsSourceBtn) {
        saveHostsSourceBtn.addEventListener('click', function() {
            const name = document.getElementById('hosts-source-name').value;
            const url = document.getElementById('hosts-source-url').value;
            const enable = document.getElementById('hosts-source-enable').checked;
            if (!name || !url) {
                showToast('请填写完整信息', 'warning', 8000);
                return;
            }
            const source = { name, url, enable };
            fetch('/api/hosts-sources', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(source)
            })
                .then(response => response.json())
                .then(data => {
                    const modal = bootstrap.Modal.getInstance(document.getElementById('addHostsSourceModal'));
                    if (modal) modal.hide();
                    document.getElementById('add-hosts-source-form').reset();
                    loadHostsSources();
                    loadCurrentHosts();
                    showToast('Hosts源已添加', 'success');
                })
                .catch(error => {
                    console.error('添加Hosts源失败:', error);
                    showToast(error.message, 'danger', 10000);
                });
        });
    }
    // 刷新日志
    const refreshLogsBtn = document.getElementById('refresh-logs');
    if (refreshLogsBtn) {
        refreshLogsBtn.addEventListener('click', function() { loadLogs(); });
    }
    // 批量添加Tracker
    const saveBatchTrackersBtn = document.getElementById('save-batch-trackers');
    if (saveBatchTrackersBtn) {
        saveBatchTrackersBtn.addEventListener('click', function() {
            const domainsText = document.getElementById('tracker-domains').value;
            if (!domainsText.trim()) {
                showToast('请输入至少一个域名', 'warning', 8000);
                return;
            }
            const domains = domainsText.split('\n').map(d => d.trim()).filter(d => d);
            if (domains.length === 0) {
                showToast('请输入至少一个有效域名', 'warning', 8000);
                return;
            }
            batchAddTrackers(domains);
        });
    }
    // 运行优选脚本按钮
    const btnRunCfstScript = document.getElementById('btn-run-cfst-script');
    if (btnRunCfstScript) {
        btnRunCfstScript.addEventListener('click', function() { runCfstScript(); });
    }
    // 批量更新IP按钮
    const btnUpdateAllTrackers = document.getElementById('btn-update-all-trackers');
    if (btnUpdateAllTrackers) {
        btnUpdateAllTrackers.addEventListener('click', function() {
            const ip = document.getElementById('batch-update-ip').value.trim();
            if (!ip) {
                showToast('请输入有效的IP地址', 'warning', 8000);
                return;
            }
            const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
            if (!ipv4Regex.test(ip)) {
                showToast('请输入有效的IPv4地址，格式如：104.16.91.215', 'warning', 8000);
                return;
            }
            updateAllTrackersIp(ip);
        });
    }
    // 导入tracker按钮事件（假设id为btn-import-trackers）
    const btnImportTrackers = document.getElementById('btn-import-trackers');
    if (btnImportTrackers) {
        btnImportTrackers.addEventListener('click', function() {
            this.disabled = true;
            showToast('正在导入下载器Tracker，请耐心等待...', 'info', 12000);
            fetchWithTimeout('/api/import-trackers-from-clients', { method: 'POST' }, 180000)
                .then(response => response.json())
                .then(data => {
                    showToast(data.message || '导入完成', 'success', 10000);
                    loadTrackers();
                    loadCurrentHosts();
                })
                .catch(error => {
                    showToast('导入Tracker失败: ' + error.message, 'danger', 10000);
                })
                .finally(() => {
                    this.disabled = false;
                });
        });
    }
    // 清空hosts并更新按钮
    const btnClearAndUpdateHosts = document.getElementById('btn-clear-and-update-hosts');
    if (btnClearAndUpdateHosts) {
        btnClearAndUpdateHosts.addEventListener('click', function() {
            if (!confirm('确定要清空系统hosts文件并重新生成吗？此操作不可恢复，建议先备份。')) return;
            btnClearAndUpdateHosts.disabled = true;
            showToast('正在清空hosts文件并更新，请稍候...', 'info', 10000);
            fetch('/api/clear-and-update-hosts', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    showToast(data.message || '已清空并更新hosts', 'success', 10000);
                    loadCurrentHosts();
                })
                .catch(error => {
                    showToast('清空并更新hosts失败: ' + error.message, 'danger', 10000);
                })
                .finally(() => {
                    btnClearAndUpdateHosts.disabled = false;
                });
        });
    }
    // 清空所有tracker按钮
    const btnClearAllTrackers = document.getElementById('btn-clear-all-trackers');
    if (btnClearAllTrackers) {
        btnClearAllTrackers.addEventListener('click', function() {
            if (!confirm('确定要清空所有tracker吗？此操作不可恢复，建议先备份。')) return;
            btnClearAllTrackers.disabled = true;
            showToast('正在清空所有tracker，请稍候...', 'info', 10000);
            fetch('/api/clear-all-trackers', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    showToast(data.message || '已清空所有tracker', 'success', 10000);
                    loadTrackers();
                    loadCurrentHosts();
                })
                .catch(error => {
                    showToast('清空所有tracker失败: ' + error.message, 'danger', 10000);
                })
                .finally(() => {
                    btnClearAllTrackers.disabled = false;
                });
        });
    }
}

// 加载控制面板数据
function loadDashboard() {
    console.log('Loading dashboard data'); // 添加日志
    // 获取调度器状态
    fetch('/api/scheduler-status')
        .then(response => response.json())
        .then(data => {
            const statusElement = document.getElementById('scheduler-status');
            const statusBadgeElement = document.getElementById('scheduler-status-badge');
            const jobsElement = document.getElementById('scheduler-jobs');
            
            if (data.running) {
                statusElement.innerHTML = '<span class="text-success">运行中</span>';
                if (statusBadgeElement) {
                    statusBadgeElement.textContent = '运行中';
                    statusBadgeElement.className = 'status-badge badge-running';
                }
            } else {
                statusElement.innerHTML = '<span class="text-danger">已停止</span>';
                if (statusBadgeElement) {
                    statusBadgeElement.textContent = '已停止';
                    statusBadgeElement.className = 'status-badge badge-stopped';
                }
            }
            
            // 清空任务列表
            jobsElement.innerHTML = '';
            
            // 添加任务
            if (data.jobs && data.jobs.length > 0) {
                data.jobs.forEach(job => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${job.name}</td>
                        <td>${job.next_run}</td>
                    `;
                    jobsElement.appendChild(row);
                });
            } else {
                jobsElement.innerHTML = '<tr><td colspan="2">暂无定时任务</td></tr>';
            }
        })
        .catch(error => {
            console.error('获取调度器状态失败:', error);
            document.getElementById('scheduler-status').innerHTML = 
                '<span class="text-danger">获取状态失败</span>';
            
            const statusBadgeElement = document.getElementById('scheduler-status-badge');
            if (statusBadgeElement) {
                statusBadgeElement.textContent = '获取失败';
                statusBadgeElement.className = 'status-badge badge-stopped';
            }
        });
}

// 加载Cloudflare配置
function loadCloudflareConfig() {
    console.log('Loading Cloudflare config'); // 添加日志
    fetch('/api/config')
        .then(response => response.json())
        .then(config => {
            const cloudflareConfig = config.cloudflare || {};
            
            // 设置表单值
            document.getElementById('cloudflare-enable').checked = 
                cloudflareConfig.enable !== undefined ? cloudflareConfig.enable : true;
            document.getElementById('cloudflare-cron').value = 
                cloudflareConfig.cron || '0 0 * * *';
        })
        .catch(error => {
            console.error('加载定时任务配置失败:', error);
            showToast('加载定时任务配置失败', 'danger', 10000);
        });
}

// 加载Trackers
function loadTrackers() {
    fetch('/api/config')
        .then(response => response.json())
        .then(config => {
            const trackers = config.trackers || [];
            const tableElement = document.getElementById('trackers-table');
            
            // 清空表格
            tableElement.innerHTML = '';
            
            // 添加Trackers
            if (trackers.length > 0) {
                trackers.forEach(tracker => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${tracker.name || ''}</td>
                        <td>${tracker.domain || ''}</td>
                        <td>${tracker.ip || '未设置'}</td>
                        <td>
                            <div class="form-check form-switch">
                                <input class="form-check-input tracker-switch" type="checkbox" 
                                    data-domain="${tracker.domain}" 
                                    ${tracker.enable ? 'checked' : ''}>
                            </div>
                        </td>
                        <td>
                            <button class="btn btn-sm btn-danger delete-tracker" 
                                data-domain="${tracker.domain}">
                                <i class="bi bi-trash"></i> 删除
                            </button>
                        </td>
                    `;
                    tableElement.appendChild(row);
                });
                
                // 绑定Tracker开关事件
                document.querySelectorAll('.tracker-switch').forEach(switchElement => {
                    switchElement.addEventListener('change', function() {
                        const domain = this.getAttribute('data-domain');
                        const enable = this.checked;
                        
                        updateTracker(domain, { enable });
                    });
                });
                
                // 绑定删除Tracker事件
                document.querySelectorAll('.delete-tracker').forEach(button => {
                    button.addEventListener('click', function() {
                        const domain = this.getAttribute('data-domain');
                        
                        if (confirm(`确定要删除Tracker "${domain}" 吗？`)) {
                            deleteTracker(domain);
                        }
                    });
                });
            } else {
                tableElement.innerHTML = '<tr><td colspan="5" class="text-center">暂无Tracker</td></tr>';
            }
        })
        .catch(error => {
            console.error('加载Trackers失败:', error);
            showToast('加载Trackers失败', 'danger', 10000);
        });
}

// 加载Hosts源
function loadHostsSources() {
    fetch('/api/config')
        .then(response => response.json())
        .then(config => {
            const sources = config.hosts_sources || [];
            const tableElement = document.getElementById('hosts-sources-table');
            
            // 清空表格
            tableElement.innerHTML = '';
            
            // 添加Hosts源
            if (sources.length > 0) {
                sources.forEach(source => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${source.name || ''}</td>
                        <td>${source.url || ''}</td>
                        <td>
                            <div class="form-check form-switch">
                                <input class="form-check-input hosts-source-switch" type="checkbox" 
                                    data-url="${source.url}" 
                                    ${source.enable ? 'checked' : ''}>
                            </div>
                        </td>
                        <td>
                            <button class="btn btn-sm btn-danger delete-hosts-source" 
                                data-url="${source.url}">
                                <i class="bi bi-trash"></i> 删除
                            </button>
                        </td>
                    `;
                    tableElement.appendChild(row);
                });
                
                // 绑定Hosts源开关事件
                document.querySelectorAll('.hosts-source-switch').forEach(switchElement => {
                    switchElement.addEventListener('change', function() {
                        const url = this.getAttribute('data-url');
                        const enable = this.checked;
                        
                        updateHostsSource(url, { enable });
                    });
                });
                
                // 绑定删除Hosts源事件
                document.querySelectorAll('.delete-hosts-source').forEach(button => {
                    button.addEventListener('click', function() {
                        const url = this.getAttribute('data-url');
                        
                        if (confirm(`确定要删除Hosts源 "${url}" 吗？`)) {
                            deleteHostsSource(url);
                        }
                    });
                });
            } else {
                tableElement.innerHTML = '<tr><td colspan="4" class="text-center">暂无Hosts源</td></tr>';
            }
        })
        .catch(error => {
            console.error('加载Hosts源失败:', error);
            showToast('加载Hosts源失败', 'danger', 10000);
        });
}

// 加载日志
function loadLogs() {
    fetch('/api/logs')
        .then(response => response.json())
        .then(data => {
            const logsElement = document.getElementById('logs');
            // 适配后端返回的带换行字符串
            if (typeof data.logs === 'string' && data.logs.length > 0) {
                logsElement.textContent = data.logs;
                logsElement.scrollTop = logsElement.scrollHeight;
            } else if (Array.isArray(data.logs) && data.logs.length > 0) {
                logsElement.textContent = data.logs.join('');
                logsElement.scrollTop = logsElement.scrollHeight;
            } else {
                logsElement.textContent = '暂无日志';
            }
        })
        .catch(error => {
            console.error('加载日志失败:', error);
            document.getElementById('logs').textContent = '加载日志失败';
        });
}

// 加载当前Hosts文件
function loadCurrentHosts() {
    fetch('/api/current-hosts')
        .then(response => response.json())
        .then(data => {
            const hostsElement = document.getElementById('current-hosts');
            
            if (data.hosts && data.hosts.length > 0) {
                hostsElement.textContent = data.hosts.join('');
            } else {
                hostsElement.textContent = '获取hosts文件失败';
            }
        })
        .catch(error => {
            console.error('获取hosts文件失败:', error);
            document.getElementById('current-hosts').textContent = '获取hosts文件失败';
        });
}

// 更新Tracker
function updateTracker(domain, data) {
    fetch('/api/config')
        .then(response => response.json())
        .then(config => {
            // 查找并更新Tracker
            const trackers = config.trackers || [];
            let updated = false;
            
            for (let i = 0; i < trackers.length; i++) {
                if (trackers[i].domain === domain) {
                    trackers[i] = { ...trackers[i], ...data };
                    updated = true;
                    break;
                }
            }
            
            if (!updated) {
                showToast('未找到指定的Tracker', 'warning', 8000);
                return;
            }
            
            // 保存配置
            return fetch('/api/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(config)
            });
        })
        .then(response => response.json())
        .then(data => {
            showToast('Tracker已更新', 'success');
            
            // 刷新Hosts文件
            loadCurrentHosts();
        })
        .catch(error => {
            console.error('更新Tracker失败:', error);
            showToast('更新Tracker失败', 'danger', 10000);
        });
}

// 删除Tracker
function deleteTracker(domain) {
    fetch(`/api/trackers/${domain}`, {
        method: 'DELETE'
    })
        .then(response => {
            if (response.ok) {
                return response.json();
            } else {
                return response.json().then(data => {
                    throw new Error(data.detail || '删除Tracker失败');
                });
            }
        })
        .then(data => {
            showToast('Tracker已删除', 'success');
            
            // 刷新Trackers列表
            loadTrackers();
            
            // 刷新Hosts文件
            loadCurrentHosts();
        })
        .catch(error => {
            console.error('删除Tracker失败:', error);
            showToast(error.message, 'danger', 10000);
        });
}

// 更新Hosts源
function updateHostsSource(url, data) {
    showToast('正在更新Hosts源，请稍候...', 'info', 8000);
    fetch('/api/config')
        .then(response => response.json())
        .then(config => {
            // 查找并更新Hosts源
            const sources = config.hosts_sources || [];
            let updated = false;
            
            for (let i = 0; i < sources.length; i++) {
                if (sources[i].url === url) {
                    sources[i] = { ...sources[i], ...data };
                    updated = true;
                    break;
                }
            }
            
            if (!updated) {
                showToast('未找到指定的Hosts源', 'warning', 8000);
                return;
            }
            
            // 保存配置
            return fetch('/api/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(config)
            });
        })
        .then(response => response.json())
        .then(data => {
            showToast('Hosts源已更新', 'success');
            
            // 刷新Hosts文件
            loadCurrentHosts();
        })
        .catch(error => {
            console.error('更新Hosts源失败:', error);
            showToast('更新Hosts源失败', 'danger', 10000);
        });
}

// 删除Hosts源
function deleteHostsSource(url) {
    showToast('正在删除Hosts源，请稍候...', 'info', 8000);
    fetch(`/api/hosts-sources?url=${encodeURIComponent(url)}`, {
        method: 'DELETE'
    })
        .then(response => {
            if (response.ok) {
                return response.json();
            } else {
                return response.json().then(data => {
                    throw new Error(data.detail || '删除Hosts源失败');
                });
            }
        })
        .then(data => {
            showToast('Hosts源已删除', 'success');
            loadHostsSources();
            loadCurrentHosts();
        })
        .catch(error => {
            console.error('删除Hosts源失败:', error);
            showToast(error.message, 'danger', 10000);
        });
}

// 只保留一份showToast实现，放在文件底部，所有调用都用此函数
function showToast(message, type = 'info', delay = 8000) {
    console.log('显示Toast:', message, type);
    // 如果已有相同内容的Toast，先关闭它
    const existingToasts = document.querySelectorAll('.toast');
    existingToasts.forEach(toast => {
        const toastBody = toast.querySelector('.toast-body');
        if (toastBody && toastBody.textContent.trim() === message) {
            const bsToast = bootstrap.Toast.getInstance(toast);
            if (bsToast) {
                bsToast.hide();
            }
        }
    });
    // 创建Toast元素
    const toastElement = document.createElement('div');
    toastElement.className = `toast align-items-center text-white bg-${type} border-0`;
    toastElement.setAttribute('role', 'alert');
    toastElement.setAttribute('aria-live', 'assertive');
    toastElement.setAttribute('aria-atomic', 'true');
    toastElement.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    // 添加到页面
    let toastContainer = document.querySelector('.toast-container');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.className = 'toast-container position-fixed top-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }
    toastContainer.appendChild(toastElement);
    // 显示Toast
    const toast = new bootstrap.Toast(toastElement, {
        autohide: true,
        delay: delay
    });
    // 悬停时不消失
    let paused = false;
    let remaining = delay;
    let hideTimeout;
    toastElement.addEventListener('mouseenter', function() {
        paused = true;
        toast._config.autohide = false;
        clearTimeout(hideTimeout);
    });
    toastElement.addEventListener('mouseleave', function() {
        paused = false;
        toast._config.autohide = true;
        hideTimeout = setTimeout(() => toast.hide(), remaining);
    });
    // 记录显示时间，支持悬停恢复
    toastElement.addEventListener('shown.bs.toast', function() {
        const start = Date.now();
        hideTimeout = setTimeout(() => {
            if (!paused) toast.hide();
        }, remaining);
        toastElement.addEventListener('mouseenter', function() {
            remaining -= Date.now() - start;
        }, { once: true });
    });
    toast.show();
    // Toast隐藏后移除元素
    toastElement.addEventListener('hidden.bs.toast', function() {
        if (toastContainer.children.length <= 1) {
            document.body.removeChild(toastContainer);
        } else {
            toastContainer.removeChild(toastElement);
        }
    });
}

// fetchWithTimeout工具函数，支持超时
function fetchWithTimeout(resource, options = {}, timeout = 180000) {
    return Promise.race([
        fetch(resource, options),
        new Promise((_, reject) => setTimeout(() => reject(new Error('导入任务已提交，处理时间较长请耐心等待，稍后可刷新页面查看结果')), timeout))
    ]);
}

// 批量添加Trackers
function batchAddTrackers(domains, forceCloudflare = false) {
    showToast('正在批量添加域名...', 'info', 8000);
    fetch('/api/batch-add-domains', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ domains })
    })
    .then(response => response.json())
    .then(async data => {
        // 新增：如forceCloudflare为true，批量写入白名单
        if (forceCloudflare && Array.isArray(domains)) {
            for (const d of domains) {
                await fetch(`/api/cloudflare-domains?domain=${encodeURIComponent(d)}`, { method: 'POST' });
            }
        }
        const status = data.status || (data.message.includes('成功') ? 'success' : 'warning');
        showToast(data.message || '批量添加域名操作已完成', status, 8000);
        if (data.filtered_domains && data.filtered_domains.length > 0) {
            showToast('以下域名未检测到Cloudflare特征，已被跳过：' + data.filtered_domains.join(', '), 'warning', 8000);
        }
        if (data.details) {
            console.log('批量添加域名详情:', data.details);
        }
        const modal = bootstrap.Modal.getInstance(document.getElementById('batchAddTrackerModal'));
        if (modal) {
            modal.hide();
        }
        document.getElementById('tracker-domains').value = '';
        loadTrackers();
        loadCurrentHosts();
    })
    .catch(error => {
        console.error('批量添加域名失败:', error);
        showToast('批量添加域名失败: ' + error.message, 'danger', 10000);
    });
}

// 运行CloudflareSpeedTest优选脚本
function runCfstScript() {
    showToast('正在启动IP优选与Hosts更新任务...', 'info', 8000);
    fetch('/api/run-cfst-script', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
    })
    .then(response => response.json())
    .then(data => {
        showToast(data.message || 'IP优选任务已启动', 'success', 8000);
        // 延迟一段时间后，确保IP优选有足够时间完成
        setTimeout(() => {
            // 先调用更新hosts API
            fetch('/api/update-hosts', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            })
            .then(res => res.json())
            .then(hostData => {
                showToast(hostData.message || 'Hosts文件已更新', 'success', 8000);
                // 然后刷新界面显示
                loadDashboard();
                loadTrackers(); // 强制刷新Tracker列表，确保IP显示最新
                loadCurrentHosts();
            })
            .catch(error => {
                console.error('更新Hosts失败:', error);
                showToast('更新Hosts失败: ' + error.message, 'danger', 10000);
            });
        }, 5000); // 增加等待时间到5秒，确保IP优选有足够时间完成
    })
    .catch(error => {
        console.error('启动IP优选任务失败:', error);
        showToast('启动IP优选任务失败: ' + error.message, 'danger', 10000);
    });
}

// 批量更新所有Tracker的IP
function updateAllTrackersIp(ip) {
    showToast('正在更新所有Tracker的IP...', 'info', 8000);
    
    fetch(`/api/update-all-trackers?ip=${encodeURIComponent(ip)}`, {
        method: 'POST'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('更新所有Tracker的IP失败');
        }
        return response.json();
    })
    .then(data => {
        showToast(data.message || `已将所有Tracker的IP更新为 ${ip}`, 'success', 8000);
        
        // 重新加载Tracker列表
        loadTrackers();
        
        // 更新hosts文件显示
        loadCurrentHosts();
    })
    .catch(error => {
        console.error('更新所有Tracker的IP失败:', error);
        showToast('更新所有Tracker的IP失败: ' + error.message, 'danger', 10000);
    });
}

// 显示操作结果
function showActionResult(message, type = 'info') {
    const resultElement = document.getElementById('action-result');
    if (!resultElement) return;
    
    resultElement.innerHTML = `<div class="alert alert-${type} mt-3">${message}</div>`;
    
    // 5秒后自动清除
    setTimeout(() => {
        resultElement.innerHTML = '';
    }, 5000);
}

// 显示进度模态框
function showProgressModal(message) {
    // 显示进度弹窗
    $("#progressModal").modal({
        backdrop: 'static',
        keyboard: false
    });
    $("#progressModal").modal("show");
    
    // 设置消息
    $("#progress-message").text(message || "请稍候，操作正在进行中...");
    
    // 返回一个轮询函数，可以用于检查任务状态
    return function pollTaskStatus(callback) {
        let intervalId = setInterval(function() {
            $.ajax({
                url: "/api/task-status",
                type: "GET",
                success: function(response) {
                    console.log('Task status response:', response);
                    
                    // 更新进度信息
                    if (response.message) {
                        $("#progress-message").text(response.message);
                    }
                    
                    // 如果任务完成，停止轮询并执行回调
                    if (response.status === "done") {
                        clearInterval(intervalId);
                        hideProgressModal();
                        if (typeof callback === 'function') {
                            callback(response);
                        }
                    }
                },
                error: function(xhr, status, error) {
                    console.error('Poll task status failed:', status, error);
                    // 出错时也停止轮询
                    clearInterval(intervalId);
                    hideProgressModal();
                    showToast("查询任务状态失败: " + error, "danger");
                }
            });
        }, 2000); // 每2秒查询一次
        
        // 返回计时器ID，以便在需要时手动清除
        return intervalId;
    };
}

function hideProgressModal() {
    $("#progressModal").modal("hide");
}

// ========== 前端输入校验增强 ========== //

function enhanceInputValidation() {
    // CRON表达式校验
    const cronInput = document.getElementById('cloudflare-cron');
    if (cronInput) {
        cronInput.addEventListener('input', function() {
            const value = cronInput.value.trim();
            const resultSpan = document.getElementById('cloudflare-save-result');
            if (!isValidCron(value)) {
                resultSpan.textContent = 'CRON格式无效，需5段数字/星号/逗号/横线';
                resultSpan.className = 'ms-2 text-danger';
            } else {
                resultSpan.textContent = '';
            }
        });
    }
    // hosts源URL校验和自动补全
    const hostsUrlInput = document.getElementById('hosts-source-url');
    if (hostsUrlInput) {
        hostsUrlInput.addEventListener('blur', function() {
            let value = hostsUrlInput.value.trim();
            if (value && !/^https?:\/\//i.test(value)) {
                value = 'https://' + value;
                hostsUrlInput.value = value;
            }
            if (!isValidUrl(value)) {
                hostsUrlInput.classList.add('is-invalid');
            } else {
                hostsUrlInput.classList.remove('is-invalid');
            }
        });
    }
    // 下载器主机和端口校验
    const qbHost = document.getElementById('qbittorrent-host');
    const qbPort = document.getElementById('qbittorrent-port');
    const trHost = document.getElementById('transmission-host');
    const trPort = document.getElementById('transmission-port');
    [qbHost, trHost].forEach(input => {
        if (input) {
            input.addEventListener('blur', function() {
                if (!isValidHost(input.value.trim())) {
                    input.classList.add('is-invalid');
                } else {
                    input.classList.remove('is-invalid');
                }
            });
        }
    });
    [qbPort, trPort].forEach(input => {
        if (input) {
            input.addEventListener('blur', function() {
                if (!isValidPort(input.value.trim())) {
                    input.classList.add('is-invalid');
                } else {
                    input.classList.remove('is-invalid');
                }
            });
        }
    });
}

function isValidCron(str) {
    // 简单校验：5段，允许数字、*、,、-、/，不做复杂语义校验
    return /^([\d\*\/,\-]+\s+){4}[\d\*\/,\-]+$/.test(str);
}
function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}
function isValidHost(host) {
    // 简单校验IP或域名
    return /^(?:[a-zA-Z0-9\-\.]+|\d{1,3}(?:\.\d{1,3}){3})$/.test(host);
}
function isValidPort(port) {
    const n = Number(port);
    return Number.isInteger(n) && n >= 1 && n <= 65535;
}

// ===== Cloudflare白名单管理UI =====
window.loadCloudflareDomains = function() {
    fetch('/api/cloudflare-domains')
        .then(res => res.json())
        .then(data => {
            const list = data.cloudflare_domains || [];
            const container = document.getElementById('cloudflare-domains-list');
            if (!container) return;
            container.innerHTML = '';
            list.forEach(domain => {
                const li = document.createElement('li');
                li.className = 'list-group-item d-flex justify-content-between align-items-center';
                li.innerHTML = `<span>${domain}</span><button class="btn btn-sm btn-danger" onclick="removeCloudflareDomain('${domain}')">移除</button>`;
                container.appendChild(li);
            });
        });
}
window.addCloudflareDomain = function() {
    const input = document.getElementById('cloudflare-domain-input');
    let domain = input.value.trim();
    if (!domain) return;
    // 自动去除http/https前缀和路径，保证与tracker一致
    domain = domain.replace(/^https?:\/\//i, '').split('/')[0];
    fetch(`/api/cloudflare-domains?domain=${encodeURIComponent(domain)}`, { method: 'POST' })
        .then(() => {
            input.value = '';
            loadCloudflareDomains();
            showToast('已添加到Cloudflare白名单', 'success');
        });
}
window.removeCloudflareDomain = function(domain) {
    fetch(`/api/cloudflare-domains?domain=${encodeURIComponent(domain)}`, { method: 'DELETE' })
        .then(() => {
            loadCloudflareDomains();
            showToast('已移除Cloudflare白名单', 'success');
        });
}