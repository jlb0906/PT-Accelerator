#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
# --------------------------------------------------------------
#	项目: CloudflareSpeedTest 自动更新 Hosts
#	版本: 1.0.4
#	作者: XIU2
#	项目: https://github.com/XIU2/CloudflareSpeedTest
# --------------------------------------------------------------

# 设置工作目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
cd "$SCRIPT_DIR" || exit 1

# 日志函数
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

_CHECK() {
	while true
		do
		if [[ ! -e "nowip_hosts.txt" ]]; then
			echo -e "该脚本的作用为 CloudflareST 测速后获取最快 IP 并替换 Hosts 中的 Cloudflare CDN IP。\n使用前请先阅读：https://github.com/XIU2/CloudflareSpeedTest/issues/42#issuecomment-768273848"
			echo -e "第一次使用，请先将 Hosts 中所有 Cloudflare CDN IP 统一改为一个 IP。"
			read -e -p "输入该 Cloudflare CDN IP 并回车（后续不再需要该步骤）：" NOWIP
			if [[ ! -z "${NOWIP}" ]]; then
				echo ${NOWIP} > nowip_hosts.txt
				break
			else
				echo "该 IP 不能是空！"
			fi
		else
			break
		fi
	done
}

_UPDATE() {
	echo -e "开始测速..."
	NOWIP=$(head -1 nowip_hosts.txt)
	log "当前的IP是: ${NOWIP}"
	
	# 查找CloudflareSpeedTest程序
	CFST_PATH=""
	possible_paths=(
		"./CloudflareST"
		"/usr/local/bin/CloudflareST"
		"/usr/bin/CloudflareST"
		"/app/CloudflareST"
		"/app/CloudflareST_linux_amd64/CloudflareST"
	)

	for path in "${possible_paths[@]}"; do
		if [[ -x "$path" ]]; then
			CFST_PATH="$path"
			log "找到CloudflareSpeedTest: $CFST_PATH"
			break
		fi
	done

	if [[ -z "$CFST_PATH" ]]; then
		log "错误: 未找到CloudflareSpeedTest可执行文件"
		exit 1
	fi

	# 检查ip.txt文件
	IP_FILE="ip.txt"
	if [[ ! -f "$IP_FILE" ]]; then
		log "未找到IP文件，尝试从其他位置复制"
		find / -name "ip.txt" -type f -print 2>/dev/null | head -1 | xargs -I {} cp {} "$IP_FILE"
		
		if [[ ! -f "$IP_FILE" ]]; then
			log "仍然找不到IP文件，创建一个基本的文件"
			cat > "$IP_FILE" << EOL
# Cloudflare IP Ranges
1.1.1.0/24
1.0.0.0/24
104.16.0.0/12
172.64.0.0/13
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
EOL
		fi
	fi
	
	log "使用IP文件: $IP_FILE"
	log "CloudflareSpeedTest路径: $CFST_PATH"

	# 这里可以自己添加、修改 CloudflareST 的运行参数
	# 添加 -dd 参数只测延迟，避免下载测速时间过长
	# 添加 -p 0 参数不直接显示结果，仅保存到文件
	# 添加 -f 参数明确指定IP文件位置
	log "执行命令: $CFST_PATH -dd -p 0 -f $IP_FILE -o result_hosts.txt"
	$CFST_PATH -dd -p 0 -f $IP_FILE -o "result_hosts.txt"
	
	CFST_EXIT_CODE=$?
	log "CloudflareSpeedTest 退出代码: $CFST_EXIT_CODE"

	# 如果需要 "找不到满足条件的 IP 就一直循环测速下去"，那么可以将下面的两个 exit 0 改为 _UPDATE 即可
	if [[ ! -e "result_hosts.txt" ]]; then
		log "CloudflareST 测速结果 IP 数量为 0，跳过下面步骤..."
		exit 0
	fi
	
	# 查看结果文件内容
	log "结果文件内容前5行:"
	head -n 5 result_hosts.txt

	# 下面这行代码是 "找不到满足条件的 IP 就一直循环测速下去" 才需要的代码
	# 考虑到当指定了下载速度下限，但一个满足全部条件的 IP 都没找到时，CloudflareST 就会输出所有 IP 结果
	# 因此当你指定 -sl 参数时，需要移除下面这段代码开头的 # 井号注释符，来做文件行数判断（比如下载测速数量：10 个，那么下面的值就设在为 11）
	#[[ $(cat result_hosts.txt|wc -l) > 11 ]] && echo "CloudflareST 测速结果没有找到一个完全满足条件的 IP，重新测速..." && _UPDATE


	BESTIP=$(sed -n "2,1p" result_hosts.txt | awk -F, '{print $1}')
	if [[ -z "${BESTIP}" ]]; then
		log "CloudflareST 测速结果 IP 数量为 0，跳过下面步骤..."
		exit 0
	fi
	log "找到最优IP: ${BESTIP}"
	echo ${BESTIP} > nowip_hosts.txt
	echo -e "\n旧 IP 为 ${NOWIP}\n新 IP 为 ${BESTIP}\n"

	log "开始备份 Hosts 文件（hosts_backup）..."
	if [[ -f "/etc/hosts" ]]; then
	\cp -f /etc/hosts /etc/hosts_backup
	else
		log "警告: 找不到 /etc/hosts 文件"
	fi

	log "开始替换..."
	
	# 使用更精确的替换方式，只替换在PT-Accelerator区域内的IP
	if [[ -f "/etc/hosts" ]]; then
		# 备份hosts文件
		cp -f /etc/hosts /etc/hosts.cfst.bak
		
		# 检查是否包含PT-Accelerator标记
		if grep -q "PT-Accelerator" /etc/hosts; then
			# 查找PT站点加速部分的开始和结束行号
			PT_START=$(grep -n "PT站点加速开始" /etc/hosts | cut -d: -f1)
			PT_END=$(grep -n "PT站点加速结束" /etc/hosts | cut -d: -f1)
			
			if [[ -n "$PT_START" && -n "$PT_END" ]]; then
				# 提取PT站点区域，替换IP，然后更新回hosts文件
				PT_SECTION=$(sed -n "${PT_START},${PT_END}p" /etc/hosts)
				UPDATED_PT_SECTION=$(echo "$PT_SECTION" | sed "s/${NOWIP}/${BESTIP}/g")
				
				# 使用临时文件进行安全替换
				cat /etc/hosts > /tmp/hosts.new
				sed -i "${PT_START},${PT_END}c\\${UPDATED_PT_SECTION}" /tmp/hosts.new
				cat /tmp/hosts.new > /etc/hosts
				rm /tmp/hosts.new
				
				log "完成 /etc/hosts 中PT站点区域的IP替换：${NOWIP} -> ${BESTIP}"
			else
				log "在 /etc/hosts 中未找到PT站点加速区域，无法精确替换"
				# 尝试全局替换
				sed -i "s/${NOWIP}/${BESTIP}/g" /etc/hosts
				log "尝试在整个 /etc/hosts 中替换IP: ${NOWIP} -> ${BESTIP}"
			fi
		else
			log "未发现PT-Accelerator标记，尝试直接替换"
			sed -i "s/${NOWIP}/${BESTIP}/g" /etc/hosts
			log "尝试在整个 /etc/hosts 中替换IP: ${NOWIP} -> ${BESTIP}"
		fi
	else
		log "找不到 /etc/hosts 文件"
	fi
	
	# 如果在容器环境中，尝试替换挂载的hosts文件
	if [[ -f "/mnt/hosts" ]]; then
		log "发现挂载的 /mnt/hosts 文件"
		cp -f /mnt/hosts /mnt/hosts.cfst.bak
		
		# 检查是否包含PT-Accelerator标记
		if grep -q "PT-Accelerator" /mnt/hosts; then
			# 查找PT站点加速部分的开始和结束行号
			PT_START=$(grep -n "PT站点加速开始" /mnt/hosts | cut -d: -f1)
			PT_END=$(grep -n "PT站点加速结束" /mnt/hosts | cut -d: -f1)
			
			if [[ -n "$PT_START" && -n "$PT_END" ]]; then
				# 提取PT站点区域，替换IP，然后更新回hosts文件
				PT_SECTION=$(sed -n "${PT_START},${PT_END}p" /mnt/hosts)
				UPDATED_PT_SECTION=$(echo "$PT_SECTION" | sed "s/${NOWIP}/${BESTIP}/g")
				
				# 使用临时文件进行安全替换
				cat /mnt/hosts > /tmp/mnt_hosts.new
				sed -i "${PT_START},${PT_END}c\\${UPDATED_PT_SECTION}" /tmp/mnt_hosts.new
				cat /tmp/mnt_hosts.new > /mnt/hosts
				rm /tmp/mnt_hosts.new
				
				log "完成 /mnt/hosts 中PT站点区域的IP替换：${NOWIP} -> ${BESTIP}"
			else
				log "在 /mnt/hosts 中未找到PT站点加速区域，无法精确替换"
				# 尝试全局替换
				sed -i "s/${NOWIP}/${BESTIP}/g" /mnt/hosts
				log "尝试在整个 /mnt/hosts 中替换IP: ${NOWIP} -> ${BESTIP}"
			fi
		else
			log "未发现PT-Accelerator标记，尝试直接替换"
			sed -i "s/${NOWIP}/${BESTIP}/g" /mnt/hosts
			log "尝试在整个 /mnt/hosts 中替换IP: ${NOWIP} -> ${BESTIP}"
		fi
	fi
	
	# 更新nowip_hosts.txt文件，记录最新IP
	echo "${BESTIP}" > nowip_hosts.txt
	log "已更新 nowip_hosts.txt 文件为新IP: ${BESTIP}"
	
	log "完成所有替换操作"
}

_CHECK
_UPDATE