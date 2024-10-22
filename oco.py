# -*- coding:utf-8 -*-
import json
import os
import re
import argparse
import subprocess
import sys
from collections import OrderedDict

CONFIG_FILE = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "./irq_config.json"))
SYSTEM_CONFIG_DICT = OrderedDict()
SYSCTL_TEMPLATE = """
# General optimization
# Increase the file limit for the entire system, generally set to ten percent of the system RAM size, in bytes
fs.file-max = 1048576
fs.nr_open = 1048576
fs.aio-max-nr = 1048576
fs.inotify.max_user_watches = 1048576
fs.inotify.max_user_instances = 1048576
# Modify the length of the message queue
kernel.msgmnb = 33554432
kernel.msgmax = 33554432
kernel.shmmax = 18446744073692774399
vm.max_map_count = 1048576
# Clean up memory when dirty data exceeds 5%
vm.dirty_background_ratio=5
# Limit IO when dirty data reaches 40% of memory, until dirty data is written to disk. The larger this value, the more efficient the read and write requirements, but the data is not very important.
vm.dirty_ratio=40
# Control memory over-allocation. This value affects the system's memory management. Generally, we want the system to be able to over-allocate memory, so set it to 1.
vm.overcommit_memory = 1
vm.swappiness = 1

# Network general settings
# This indicates that the system limits the local port range to between 1024 and 65000.
# Please note that the minimum value of the local port range must be greater than or equal to 1024; and the maximum value of the port range should be less than or equal to 65535
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_fastopen = 1
# Recommended to enable MTU probing for hosts that have enabled jumbo frames. Default is 1
net.ipv4.tcp_mtu_probing= 0
# Indicates whether to reuse TIME-WAIT sockets. Allowing TIME-WAIT sockets to be reused for new TCP connections, default is 0, indicating closed;
net.ipv4.tcp_tw_reuse = 1
# The maximum length of the listening queue for each port in the system. This value affects the system's concurrent connection capabilities. Generally, this value should be set to half of the expected concurrent connections of the server. For example, if your server expects to have 2000000 concurrent connections, you can set this value to 1000000.
net.core.somaxconn = 100000
# The size of the secondary buffer for each socket. This value affects the system's network performance. Generally, this value should be set to 0.03 times the expected concurrent connections of the server. For example, if your server expects to have 2000000 concurrent connections, you can set this value to 60000, but since the upper limit of this value is 65535, we set it to 65535.
net.core.optmem_max = 65535
# Enable selective acknowledgment (1 means enable), to improve performance by selectively acknowledging out-of-order received packets, allowing the sender to only send lost packet segments,
# (For WAN communication) this option should be enabled, but it will increase CPU usage. Default is 1
net.ipv4.tcp_sack = 1
# TCP timestamps (will add 12 bytes to the TCP packet header),
# Enable a more accurate method for RTT calculation than retransmission timeout (refer to RFC 1323) to achieve better performance. This option should be enabled. Default is 1
# If the server uses NAT function, timestamps cannot be turned on
net.ipv4.tcp_timestamps = 1
# Enable window scaling defined by RFC 1323, to support TCP windows over 64KB, this value must be enabled (1 means enabled),
# The TCP window can be up to 1GB, and it only takes effect when both sides of the TCP connection are enabled. Default is 1
net.ipv4.tcp_window_scaling = 1
# The maximum value of the save queue when the speed of the network card receiving packets is greater than the speed of kernel processing. This value affects the system's network performance. Generally, this value should be set to half of the expected concurrent connections of the server. For example, if your server expects to have 500000 concurrent connections, you can set this value to 250000.
net.core.netdev_max_backlog = 800000
# The maximum number of TIME_WAIT sockets allowed by the operating system. This value affects the system's concurrent connection capabilities. Generally, this value should be set to 0.72 times the expected concurrent connections of the server. For example, if your server expects to have 2000000 concurrent connections, you can set this value to 1440000.
net.ipv4.tcp_max_tw_buckets = 1440000
# Control the maximum time of TCP connection in FIN_WAIT_2 state. This value affects TCP performance. Generally, we want this value to be as small as possible to quickly release unused connections, so set it to 15.
net.ipv4.tcp_fin_timeout = 15
# The option is used to set the maximum number of TCP sockets in the system that are not associated with any user file handle.
# If this number is exceeded, isolated connections will be reset immediately and a warning message will be printed.
# This limit is just to prevent simple DoS attacks. You can't rely too much on this limit or even artificially reduce this value, in more cases you should increase this value. Default 262144
net.ipv4.tcp_max_orphans = 3276800
# The frequency of TCP sending keepalive messages when keepalive is enabled. This value affects TCP performance. Generally, we want this value to be as small as possible to quickly detect dead connections, so set it to 300.
net.ipv4.tcp_keepalive_time = 60
# The number of TCP sending keepalive probes. This value affects TCP performance. Generally, we want this value to be as small as possible to quickly detect dead connections, so set it to 5.
net.ipv4.tcp_keepalive_probes = 5
# The interval time of TCP sending keepalive probes. This value affects TCP performance. Generally, we want this value to be as small as possible to quickly detect dead connections, so set it to 15.
net.ipv4.tcp_keepalive_intvl = 15
# for http-ts live stream, set the tcp_retries2 to 10, beacuse the http-ts live stream will be disconnected frequently
net.ipv4.tcp_retries2 = 10
# The number of retries for the first SYN request. This value affects TCP performance. Generally, we want this value to be as small as possible to quickly establish connections, so set it to 4.
net.ipv4.tcp_retries1 = 4
# Represents the length of the SYN queue, the default is 2048, increasing the queue length to 8192 can accommodate more network connections waiting for connection.
# The maximum length of the SYN request queue received during the TCP three-way handshake establishment phase, the maximum value of the records that have not yet received client confirmation information, the default is 2048
net.ipv4.tcp_max_syn_backlog = 204800
net.ipv4.ipfrag_high_thresh = 33554432
net.ipv4.ipfrag_low_thresh = 32505856
net.core.netdev_budget = 1000
net.core.netdev_budget_usecs = 10000

# Parameters to improve the speed of pulling streams
# Control the refresh of the routing cache. Enabling it can reduce the delay when the route changes, but it will increase memory consumption
net.ipv4.route.flush = 1
# Control the refresh of the IPv6 routing cache. Enabling it can reduce the delay when the route changes, but it will increase memory consumption
net.ipv6.route.flush = 1
# Prohibit the preservation of TCP metrics. Enabling it can effectively improve the speed of transmission.
net.ipv4.tcp_no_metrics_save = 1
# Control whether TCP starts slowly after idle. Turning it off can effectively improve the speed of transmission.
net.ipv4.tcp_slow_start_after_idle = 0
# Used to control the automatic adjustment of the receive buffer. It can improve throughput for networks with high latency.
net.ipv4.tcp_moderate_rcvbuf=0
# Used to set the TCP window expansion factor, the larger the theoretical throughput, but it will increase memory consumption.
net.ipv4.tcp_adv_win_scale= -2
# default is 4294967295
net.ipv4.tcp_notsent_lowat = 131072
# Set the default queue scheduling algorithm. This value affects the system's network performance. Generally, we want to use the fair queue (fq) algorithm, so set it to fq.
net.core.default_qdisc = fq
# Set the TCP congestion control algorithm. This value affects TCP performance. Generally, we want to use the BBR algorithm, so set it to bbr.
net.ipv4.tcp_congestion_control = bbr


# Memory Buffer Optimization
# Depending on the actual conditions of the service, it may be necessary to set a higher maximum value to provide a larger cache space for network connections.
# Explanation: The first value is the minimum number of bytes allocated for the socket send buffer; the second value is the default value (this value will be overridden by wmem_default), the buffer can grow to this value when the system load is not heavy; the third value is the maximum number of bytes for the send buffer space (this value will be overridden by wmem_max).
# The size of the read/write buffer memory allocated for each TCP connection, in bytes.
# Generally allocated according to the default value, the example above is both read and write are 8KB, a total of 16KB.
# The default is 4096 16384 4194304.
# The number of connections that 1.6GB of TCP memory can accommodate is approximately 1600MB/16KB = 100K = 100,000.
# The number of connections that 4.0GB of TCP memory can accommodate is approximately 4000MB/16KB = 250K = 250,000.
# The minimum value, default value, and maximum value of the TCP receive window size (in bytes).
# 带宽延迟积(BDP) = 带宽 * 延迟, 假设10Gbps * 300ms, 那么BDP = 10 * 10^9 * 0.3 = 3 * 10^9 / 8 = 375MB
# tcp_adv_win_scale= -2, 375MB * 4 = 1500MB, 1500MB / 16KB = 93750
# 假设400mbps * 300ms, 那么BDP = 400 * 10^6 * 0.3 = 120 * 10^6 / 8 = 15MB
# tcp_adv_win_scale= -2, 15MB * 4 = 60MB, 60MB / 16KB = 3750
net.ipv4.tcp_rmem = 8192 193072500 1610612736
# The minimum value, default value, and maximum value of the TCP send window size (in bytes).
net.ipv4.tcp_wmem = 8192 193072500 1610612736
# The default receive window size (in bytes).
net.core.rmem_default = 193072500
# The default send window size (in bytes).
net.core.wmem_default = 193072500
# The maximum value of the receive window size (in bytes).
net.core.rmem_max = 1610612736
# The maximum value of the send window size (in bytes).
net.core.wmem_max = 1610612736
net.ipv4.udp_mem = 8388608 12582912 16777216
# disable ipv6
# net.ipv6.conf.all.disable_ipv6=1
# net.ipv6.conf.default.disable_ipv6=1
# net.ipv6.conf.lo.disable_ipv6 = 1

# Security Settings
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.default.forwarding = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.forwarding = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.conf.all.proxy_arp = 0

net.ipv4.tcp_congestion_control = tsunami
\n"""


def check_installed(command):
    """
    Check if a command exists
    :param command:
    :return:
    """
    if os.system(f"command -v {command} > /dev/null") == 0:
        return True
    else:
        return False


def get_the_network_card_name(return_all=False):
    """
    获取网卡名称
    :return:
    """
    # 获取网卡名称
    result = run_cmd('ip addr', capture_output=True)
    lines = result.stdout.decode().split('\n')
    # Initialize a dictionary to store the NIC names and IP addresses
    nic_info = OrderedDict()
    nic_name = ''
    # Iterate over the lines
    for line in lines:
        # If the line contains a NIC name
        if re.match(r'\d+:\s+\w+:', line):
            # Extract the NIC name
            nic_name = re.findall(r'\d+:\s+(\w+):', line)[0]
            # If the NIC is a physical NIC (not a virtual NIC like 'lo')
            if not nic_name.startswith('lo'):
                nic_info[nic_name] = set()
            else:
                nic_name = None
        # If the line contains an IP address
        elif re.match(r'\s+inet\s+\d+\.\d+\.\d+\.\d+', line) and nic_name:
            # Extract the IP address
            ip_address = re.findall(r'\s+inet\s+(\d+\.\d+\.\d+\.\d+)', line)[0]
            # Add the IP address to the last NIC in the dictionary
            nic_info[nic_name].add(ip_address)

    # nic_info转成列表, key作为列表的第一个元素, value作为列表的第二个元素
    nic_info = [(key, value) for key, value in nic_info.items()]
    # 如果只有一个网卡, 则直接返回
    if len(nic_info) == 1:
        if return_all:
            return nic_info
        return nic_info[0][0]
    # 如果有多个网卡, 则提示用户选择
    else:
        if return_all:
            return nic_info
        print('Multiple network cards detected:')
        for index, value in enumerate(nic_info):
            print(f'{index}: {value[0]}[{", ".join(value[1])}]')
        nic_index = input('Select the network card to configure: ')
        nic_name = nic_info[int(nic_index)][0]
        print(f'You selected {nic_name}')
        return nic_name


def check_nic_exists(nic):
    all_nics = get_the_network_card_name(return_all=True)
    # 判断nic是否在所有的网卡中
    if nic not in [i[0] for i in all_nics]:
        print(f'Network card {nic} not found.')
        sys.exit(1)


def cpus2mask(cpus, cpus_count):
    """
    Convert list of CPU cores to masked string
    :param cpus:
    :param cpus_count:
    :return:
    """
    # round up to the nearest multiple of 32
    mask_len = cpus_count // 32 + 1
    # initialize mask to all 0s
    mask = [0] * mask_len
    # set bits for each CPU core
    for cpu in cpus:
        mask[cpu // 32] |= 1 << (cpu % 32)
    # convert mask to string
    mask_string = ""
    # note: mask is in little-endian order, so reverse it
    mask.reverse()
    for index, i in enumerate(mask):
        if mask_string:
            mask_string += ","
        # if last mask, only use the remaining bits
        if index == 0 and len(mask) > 1:
            core_count = cpus_count % 32
        else:
            core_count = 32
        tmp_mask_string = f"{i:08x}"
        # 1 hex digit per 4 bits, so trim leading 0s
        if core_count < 32:
            mask_hex = format((1 << core_count) - 1, 'x')
            tmp_mask_string = tmp_mask_string[8 - len(mask_hex):]
        mask_string += tmp_mask_string
    return mask_string


def run_cmd(cmd, assert_success=False, capture_output=False, env=None):
    """
    Run a command and return the result or error, without displaying the run output
    :param cmd:
    :param assert_success:
    :param capture_output:
    :param env:
    :return:
    """
    if not env:
        env = os.environ.copy()
    # 兼容python3.6
    if sys.version_info < (3, 7):
        result = subprocess.run(cmd, shell=True, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        result = subprocess.run(cmd, shell=True, env=env, capture_output=capture_output)
    # Assert the command ran successfully
    if assert_success and result.returncode != 0:
        stderr = result.stderr.decode() if result.stderr else ''
        if "no ring parameters changed, aborting" in stderr:
            return result
        print("Command '" + cmd + "' failed with exit status code '" + str(
            result.returncode) + "'.\n\nExiting now.\nTry running the script again.")
        if result.stderr:
            print(result.stderr.decode())
        sys.stdout.flush()
        sys.stderr.flush()
        sys.exit(1)
    return result


def set_limit():
    """
    check limits.conf
    if not add soft nofile, then add:
    * soft nproc 11000
    * hard nproc 11000
    * soft nofile 655350
    * hard nofile 655350

    root soft nproc 11000
    root hard nproc 11000
    root soft nofile 655350
    root hard nofile 655350
    :return:
    """
    limit_file = '/etc/security/limits.conf'
    # 检查是否存在/etc/security/limits.conf文件
    if not os.path.exists(limit_file):
        print(f'{limit_file} not found!')
        sys.exit(1)
    # 检查是否存在655350的nofile
    with open(limit_file, 'r') as f:
        content = f.read()
    if '655350' not in content:
        # 添加655350的nofile
        with open(limit_file, 'a') as f:
            f.write("""
* soft memlock unlimited
* hard memlock unlimited
* soft nproc 1048576
* hard nproc 1048576
* soft nofile 1048576
* hard nofile 1048576
root soft memlock unlimited
root hard memlock unlimited
root soft nproc 1048576
root hard nproc 1048576
root soft nofile 1048576
root hard nofile 1048576
            \n""")
        print('655350 nofile added!')
    else:
        print('655350 nofile found!')


def setup_kernel_parameters():
    """
    设置内核参数
    :return:
    """
    # 设置内核参数
    # 检查是否存在/etc/sysctl.conf文件
    sysctl_file = '/etc/sysctl.conf'
    if not os.path.exists(sysctl_file):
        print(f'{sysctl_file} not found!')
        sys.exit(1)
    # 检查是否存在net.ipv4.tcp_congestion_control = tsunami
    with open(sysctl_file, 'r') as f:
        content = f.read()
    if 'General optimization' not in content:
        # 检测内核拥塞算法是否包含tsunami
        result = run_cmd('sysctl net.ipv4.tcp_congestion_control', capture_output=True)
        sysctl_content = SYSCTL_TEMPLATE
        if 'tsunami' not in result.stdout.decode():
            sysctl_content = sysctl_content.replace('tsunami', 'bbr')
        # 添加net.ipv4.tcp_congestion_control = tsunami
        with open(sysctl_file, 'w') as f:
            f.write(sysctl_content)
        print('kernel parameters added!')
        run_cmd('sysctl -p', assert_success=True)
    else:
        print('kernel parameters found!')


def set_network_queue():
    """
    Set network card queue size.
    :return:
    """
    if "ring_rx" not in SYSTEM_CONFIG_DICT:
        setup_config(True)
        load_config()
    rx_queue = SYSTEM_CONFIG_DICT.get('rx_queue', 0)
    tx_queue = SYSTEM_CONFIG_DICT.get('tx_queue', 0)
    other_queue = SYSTEM_CONFIG_DICT.get('other_queue', 0)
    combined_queue = SYSTEM_CONFIG_DICT.get('combined_queue', 0)
    nic = SYSTEM_CONFIG_DICT['nic']
    if rx_queue > 0:
        # ethtool -L eno49 combined 30
        print(f"Setting network card {nic} RX queue size to {rx_queue}")
        result = run_cmd(f'ethtool -L {nic} rx {rx_queue}', capture_output=True)
        print(result.stdout.decode())
    if tx_queue > 0:
        print(f"Setting network card {nic} TX queue size to {tx_queue}")
        result = run_cmd(f'ethtool -L {nic} tx {tx_queue}', capture_output=True)
        print(result.stdout.decode())
    if other_queue > 0:
        print(f"Setting network card {nic} Other queue size to {other_queue}")
        result = run_cmd(f'ethtool -L {nic} other {other_queue}', capture_output=True)
        print(result.stdout.decode())
    if combined_queue > 0:
        print(f"Setting network card {nic} Combined queue size to {combined_queue}")
        result = run_cmd(f'ethtool -L {nic} combined {combined_queue}', capture_output=True)
        print(result.stdout.decode())
    print(f"Setting network card {nic} GSO, GRO, TSO on")
    result = run_cmd(f'ethtool -K {nic} gso on gro on tso on', capture_output=True, assert_success=False)
    print(result.stdout.decode())


def get_irqs_for_nic(nic):
    """
    Get all IRQs for a given network interface card (NIC) using NIC name first, then bus-info if necessary.
    :param nic: Network interface card name.
    :return: List of IRQs.
    """
    with open('/proc/interrupts', 'r') as f:
        interrupts = f.read()

    # Try to find IRQs using the NIC name
    pattern = rf'(\d+):.*{nic}'
    irqs = re.findall(pattern, interrupts)

    if not irqs:
        print(f'No IRQs found for network card {nic}, will try to find IRQs by bus-info.')
        # Get the bus-info for the NIC
        result = subprocess.run(['ethtool', '-i', nic], capture_output=True, text=True)
        bus_info = None
        for line in result.stdout.split('\n'):
            if line.startswith('bus-info:'):
                bus_info = line.split()[1]
                break

        if not bus_info:
            raise ValueError(f"Could not determine bus-info for NIC {nic}")
        # Match IRQs associated with the NIC bus-info
        pattern = rf'(\d+):.*{bus_info}'
        irqs = re.findall(pattern, interrupts)
    # Remove duplicates and sort the IRQs
    irqs = sorted(set(irqs))
    return irqs


def set_irq_affinity(cpu_count, dry_run):
    """
    Set the CPU affinity of a given IRQ.
    :param cpu_count:
    :param dry_run:
    :return:
    """
    check_nic_exists(SYSTEM_CONFIG_DICT['nic'])
    nic = SYSTEM_CONFIG_DICT['nic']
    if not dry_run:
        # 停止irqbalance服务
        print('Stopping irqbalance service...')
        run_cmd('systemctl stop irqbalance', assert_success=False)
        set_network_queue()
    # 读取/proc/interrupts文件，获取所有的网卡IRQ
    with open('/proc/interrupts', 'r') as f:
        interrupts = f.read()
    try:
        irqs = get_irqs_for_nic(nic)
    except ValueError as e:
        print(e)
        sys.exit(1)
    if not irqs:
        print(f'No IRQs found for network card {nic}.')
        sys.exit(1)
    # 初始化CPU核心索引和IRQ索引
    cpu_index = 0
    irq_index = 0

    # 初始化每个CPU核心绑定的队列数量
    cpu_irq_counts = [0] * cpu_count
    cpu_irq_dict = [[] for _ in range(len(irqs))]

    # 遍历所有的网卡IRQ
    while irq_index < len(irqs):
        # 找到当前绑定的队列数量最少的CPU核心
        cpu_index = cpu_irq_counts.index(min(cpu_irq_counts))
        # 获取当前的IRQ
        irq = irqs[irq_index]

        # 更新CPU核心的掩码和绑定的队列数量
        cpu_irq_counts[cpu_index] += 1
        # 绑定当前的IRQ到当前的CPU核心
        cpu_irq_dict[irq_index].append(cpu_index)

        # 打印当前的绑定情况
        with open(f'/proc/irq/{irq}/smp_affinity_list', 'r') as f:
            affinity_cpus = f.read().strip().split(',')
            print(f'Current affinity for IRQ {irq}: CPU {", ".join(affinity_cpus)}')

        # 更新IRQ索引
        irq_index += 1

    irq_index = 0
    # 如果所有的网卡IRQ都已经绑定完毕，但是CPU核心还有剩余，那么将剩余的CPU核心绑定到不同的网卡IRQ
    while cpu_index < cpu_count - 1:
        # 找到当前绑定的队列数量最少的CPU核心
        cpu_index = cpu_irq_counts.index(min(cpu_irq_counts))
        # 获取当前的IRQ
        irq = irqs[irq_index]

        # 更新CPU核心的掩码和绑定的队列数量
        cpu_irq_counts[cpu_index] += 1
        # 绑定当前的IRQ到当前的CPU核心
        cpu_irq_dict[irq_index].append(cpu_index)

        # 打印当前的绑定情况
        with open(f'/proc/irq/{irq}/smp_affinity_list', 'r') as f:
            affinity_cpus = f.read().strip().split(',')
            print(f'Current affinity for IRQ {irq}: CPU {", ".join(affinity_cpus)}')

        # 更新IRQ索引
        irq_index += 1
        if irq_index >= len(irqs):
            irq_index = 0

    # 打印每个中断的绑定情况
    for irq_index in range(len(irqs)):
        print(f'IRQ {irqs[irq_index]}: CPU {", ".join([str(i) for i in cpu_irq_dict[irq_index]])}')

    # 提示用户是否写入文件
    if not dry_run:
        for irq in irqs:
            irq_index = irqs.index(irq)
            with open(f'/proc/irq/{irq}/smp_affinity_list', 'w') as f:
                f.write(','.join([str(i) for i in cpu_irq_dict[irq_index]]))


def set_rps_rfs(cpu_count, dry_run):
    """
    实现RFS/RPS功能
    :param cpu_count:
    :param dry_run:
    :return:
    """
    check_nic_exists(SYSTEM_CONFIG_DICT['nic'])
    nic = SYSTEM_CONFIG_DICT['nic']
    # 开启RPS功能, 并将每个队列绑定到所有的CPU核心
    # 获取网卡的队列数量大小
    qs = os.listdir(f"/sys/class/net/{nic}/queues")
    # 遍历所有的队列
    rps_sock_flow_entries = 0
    for q in qs:
        if q.startswith('rx-'):
            # 打印当前的绑定情况
            with open(f'/sys/class/net/{nic}/queues/{q}/rps_cpus', 'r') as f:
                affinity_cpus = f.read().strip().split(',')
                print(f'Current RPS affinity for queue {q}: CPU {affinity_cpus}')
            # 绑定所有的CPU核心
            mask = cpus2mask([i for i in range(cpu_count)], cpu_count)
            # 打印当前的绑定情况
            print(f'New RPS affinity for queue {q}: CPU {mask}')
            if not dry_run:
                with open(f'/sys/class/net/{nic}/queues/{q}/rps_cpus', 'w') as f:
                    f.write(mask)
            # 开启RFS功能, 并将每个队列绑定到所有的CPU核心
            # 打印当前的绑定情况
            with open(f'/sys/class/net/{nic}/queues/{q}/rps_flow_cnt', 'r') as f:
                rps_flow_cnt = f.read().strip()
                print(f'Current RFS flow count for queue {q}: {rps_flow_cnt}')
            print(f'New RFS flow count for queue {q}: 4096')
            rps_sock_flow_entries += 4096
            if not dry_run:
                with open(f'/sys/class/net/{nic}/queues/{q}/rps_flow_cnt', 'w') as f:
                    f.write('4096')
    if rps_sock_flow_entries > 0:
        rps_sock_flow_entries = max(rps_sock_flow_entries, 32768)
        # 打印当前的绑定情况
        with open('/proc/sys/net/core/rps_sock_flow_entries', 'r') as f:
            current_rps_sock_flow_entries = f.read().strip()
            print(f'Current rps_sock_flow_entries: {current_rps_sock_flow_entries}')
        print(f'New rps_sock_flow_entries: {rps_sock_flow_entries}')
        if not dry_run:
            with open('/proc/sys/net/core/rps_sock_flow_entries', 'w') as f:
                f.write(str(rps_sock_flow_entries))


def disable_rps_rfs(nic):
    """
    Disable RFS/RPS for a given network interface card.
    :param nic: Network interface card name.
    :return: None
    """
    # Check if the user has root privileges
    if os.geteuid() != 0:
        print('This script must be run as root!')
        sys.exit(1)
    if not nic:
        nic = SYSTEM_CONFIG_DICT['nic']
    check_nic_exists(nic)
    # Get the queue directories for the NIC
    qs = os.listdir(f"/sys/class/net/{nic}/queues")

    # Iterate over the queues
    for q in qs:
        if q.startswith('rx-'):
            # Set the RPS CPUs mask to 0 (disable RPS)
            with open(f'/sys/class/net/{nic}/queues/{q}/rps_cpus', 'w') as f:
                f.write('0')
            # Set the RFS flow count to 0 (disable RFS)
            with open(f'/sys/class/net/{nic}/queues/{q}/rps_flow_cnt', 'w') as f:
                f.write('0')

    print(f'RFS/RPS has been disabled for {nic}.')


def set_ring_buff(dry_run):
    """
    Set ring buffer size for network card.
    :param dry_run:
    :return:
    """
    check_nic_exists(SYSTEM_CONFIG_DICT['nic'])
    nic = SYSTEM_CONFIG_DICT['nic']
    ring_rx = SYSTEM_CONFIG_DICT.get('ring_rx', 0)
    ring_tx = SYSTEM_CONFIG_DICT.get('ring_tx', 0)
    print(f"Setting ring buffer size for {nic}: RX {ring_rx}, TX {ring_tx}")
    # 设置网卡的ring buffer大小w为允许的最大值
    if not dry_run and ring_rx > 0 and ring_tx > 0:
        print("set ring buffer size to max")
        run_cmd(f'ethtool -G {nic} rx {ring_rx} tx {ring_tx}', assert_success=True, capture_output=True)


def check_dkms_auto_install():
    """
    Check if dkms_auto_install is enabled
    /usr/src/tsunami-5.4/dkms.conf
    :return:
    """
    # get kernel version
    result = run_cmd('uname -r', capture_output=True)
    kernel_version = result.stdout.decode().strip()
    # get short kernel version
    short_kernel_version = '.'.join(kernel_version.split('.')[:2])
    # check if dkms_auto_install is enabled
    dkms_file = f'/usr/src/tsunami-{short_kernel_version}/dkms.conf'
    if not os.path.exists(dkms_file):
        print(f'{dkms_file} not found! you should install dkms first!')
        sys.exit(1)
    # 检查如果不存在AUTOINSTALL=yes, 则添加
    with open(dkms_file, 'r') as f:
        lines = f.readlines()
    for line in lines:
        if line.startswith('AUTOINSTALL'):
            if line.split('=')[1].strip() == 'yes':
                print('AUTOINSTALL=yes found!')
                return
            else:
                print('AUTOINSTALL=no found!')
                break
    # 添加AUTOINSTALL=yes
    with open(dkms_file, 'a') as f:
        f.write('AUTOINSTALL=yes\n')
    print('AUTOINSTALL=yes added!')


def check_server_env():
    """
    check server environment settings.
    :return:
    """
    result = run_cmd('lsmod | grep tcp_tsunami', capture_output=True)
    if result.stdout.decode() == '':
        print('tcp_tsunami module not loaded!')
        sys.exit(1)
    result = run_cmd('sysctl net.ipv4.tcp_congestion_control', capture_output=True)
    # print(result.stdout.decode().split("=")[1].strip())
    if result.stdout.decode().split("=")[1].strip() != 'tsunami':
        print('tcp_tsunami module not enabled!')
        # sys.exit(1)
    else:
        print('tcp_tsunami module enabled!')
        check_dkms_auto_install()


def hold_kernel_version(force=False):
    """
    获取当前内核版本并锁定, 不允许升级
    :return:
    """
    # 获取当前内核版本
    result = run_cmd('uname -r', capture_output=True)
    kernel_version = result.stdout.decode().strip()
    # 打印当前内核版本
    print(f'Current kernel version: {kernel_version}')
    # 询问是否锁定
    if force or input('Hold the current kernel version? (yes/no) ') == 'yes':
        # 检查是否安装了apt-mark
        if not check_installed('apt-mark'):
            print('Installing apt-mark...')
            run_cmd('apt-get install -y apt-mark', assert_success=True)
        # 锁定内核版本
        run_cmd(f'apt-mark hold linux-image-{kernel_version} linux-headers-{kernel_version}', assert_success=True)
        print(f'Kernel version {kernel_version} has been held.')


def run_all(cpu_count):
    """
    运行所有的函数
    :param cpu_count:
    :return:
    """
    # 设置CPU亲和性
    print('Setting IRQ affinity...')
    set_irq_affinity(cpu_count, False)
    if SYSTEM_CONFIG_DICT.get('rps_rfs', False):
        print('Setting RPS/RFS...')
        set_rps_rfs(cpu_count, False)
    print('Hold the current kernel version...')
    hold_kernel_version(True)
    # 设置ring buffer大小
    print('Setting ring buffer size...')
    set_ring_buff(False)
    print('Check server environment settings...')
    set_limit()
    setup_kernel_parameters()
    set_cpu_performance()
    check_server_env()


def setup_auto_start():
    """
    设置开机自启动
    :return:
    """
    update = False
    nic = SYSTEM_CONFIG_DICT['nic']
    # 获取当前文件的完整路径
    script_path = os.path.abspath(sys.argv[0])
    print(f'Script path: {script_path}')
    print(f"Network card name: {nic}")
    # 查看是否已经存在irq.service文件
    if os.path.exists('/etc/systemd/system/irq.service'):
        print('Service file already exists.')
        # 询问是否要修改
        if input('Do you want to overwrite the existing service file? (yes/no) ') != 'yes':
            print('Exiting now.')
            sys.exit(1)
        else:
            print('Overwriting the existing service file...')
            update = True
    # 创建一个服务文件
    with open('/etc/systemd/system/irq.service', 'w') as f:
        f.write(f"""
[Unit]
Description=irq service
After=network.target irqbalance.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 {script_path} --all

[Install]
WantedBy=multi-user.target
        \n""")
    if not update:
        print('Service file created.')
        # 启动服务
        run_cmd('systemctl enable irq.service', assert_success=True)
        run_cmd('systemctl start irq.service', assert_success=True)
    else:
        print('Service file updated.')
        # 重启服务
        run_cmd('systemctl daemon-reload', assert_success=True)
        run_cmd('systemctl restart irq.service', assert_success=True)


def set_cpu_performance():
    """
    设置cpu性能最大模式
    :return:
    """
    # 检查是否存在cpufreq-set命令
    if not check_installed('cpufreq-set'):
        # 安装cpufreq-set命令
        print('Installing cpufreq-set...')
        run_cmd('apt-get install -y cpufrequtils', assert_success=True)
    # 获取cpu的数量
    m_cpu_count = os.cpu_count()
    # 设置cpu性能最大模式
    for i in range(m_cpu_count):
        run_cmd(f'cpufreq-set -c {i} -g performance', assert_success=True)
    print('CPU performance set to maximum mode.')


def setup_config(update=False):
    """
    先设置配置文件
    :param update:
    :return:
    """
    config_dict = OrderedDict()
    need_setup = False
    if not os.path.exists(CONFIG_FILE):
        need_setup = True
    else:
        if update:
            need_setup = True
    if not need_setup:
        return
    # 获取所有的网卡名称
    nic = get_the_network_card_name()
    config_dict['nic'] = nic
    # 获取ring buffer大小
    # 使用ethtool命令获取网卡的ring buffer大小
    result = run_cmd(f'ethtool -g {nic}', capture_output=True)
    # 使用正则表达式匹配网卡的ring buffer大小
    ring_buff = re.findall(r'Pre-set maximums:\s+RX:\s+(\d+)\s+RX Mini:\s+(\d+)\s+RX Jumbo:\s+(\d+)\s+TX:\s+(\d+)',
                           result.stdout.decode())[0]
    max_rx = int(ring_buff[0])
    max_tx = int(ring_buff[3])

    # 打印当前的ring buffer大小
    print("current ring buffer size:")
    print(result.stdout.decode())
    print(f"max_rx: {max_rx}")
    print(f"max_tx: {max_tx}")
    # 提示用户输入ring buffer大小, 如果用户没有输入或者大于最大值, 则使用最大值
    ring_rx = input(f"Please input RX ring buffer size (default {max_rx}): ")
    if not ring_rx:
        ring_rx = max_rx
    else:
        ring_rx = int(ring_rx)
        if ring_rx > max_rx:
            ring_rx = max_rx
        elif ring_rx <= 0:
            ring_rx = None
    ring_tx = input(f"Please input TX ring buffer size (default {max_tx}): ")
    if not ring_tx:
        ring_tx = max_tx
    else:
        ring_tx = int(ring_tx)
        if ring_tx > max_tx:
            ring_tx = max_tx
        elif ring_tx <= 0:
            ring_tx = None
    config_dict['ring_rx'] = ring_rx
    config_dict['ring_tx'] = ring_tx
    # 获取网卡队列的大小
    # 使用ethtool命令获取网卡的队列大小
    result = run_cmd(f'ethtool -l {nic}', capture_output=True)
    # 使用正则表达式匹配网卡的最大队列大小
    try:
        channel_param = \
            re.findall(r'Pre-set maximums:\s+RX:\s+(\d+)\s+TX:\s+(\d+)\s+Other:\s+(\d+)\s+Combined:\s+(\d+)',
                       result.stdout.decode())[0]
        # 获取网卡的队列大小
        max_rx_queue = int(channel_param[0])
        max_tx_queue = int(channel_param[1])
        max_other_queue = int(channel_param[2])
        max_combined_queue = int(channel_param[3])
        # 打印当前的队列大小
        print("current network queue parameters:")
        print(result.stdout.decode())
        print(f"rx_queue: {max_rx_queue}")
        print(f"tx_queue: {max_tx_queue}")
        print(f"other_queue: {max_other_queue}")
        print(f"combined_queue: {max_combined_queue}")

        # 提示用户输入队列大小, 如果用户没有输入或者大于最大值, 则使用最大值, 如果小于等于0, 则不更改. 如果最大值为0, 则不提示用户输入
        if max_rx_queue > 0:
            rx_queue = input(f"Please input RX queue size (default {max_rx_queue}): ")
            if not rx_queue:
                rx_queue = max_rx_queue
            else:
                rx_queue = int(rx_queue)
                if rx_queue > max_rx_queue:
                    rx_queue = max_rx_queue
                elif rx_queue <= 0:
                    rx_queue = None
        else:
            rx_queue = None
        if max_tx_queue > 0:
            tx_queue = input(f"Please input TX queue size (default {max_tx_queue}): ")
            if not tx_queue:
                tx_queue = max_tx_queue
            else:
                tx_queue = int(tx_queue)
                if tx_queue > max_tx_queue:
                    tx_queue = max_tx_queue
                elif tx_queue <= 0:
                    tx_queue = None
        else:
            tx_queue = None
        if max_other_queue > 0:
            other_queue = input(f"Please input Other queue size (default {max_other_queue}): ")
            if not other_queue:
                other_queue = max_other_queue
            else:
                other_queue = int(other_queue)
                if other_queue > max_other_queue:
                    other_queue = max_other_queue
                elif other_queue <= 0:
                    other_queue = None
        else:
            other_queue = None
        if max_combined_queue > 0:
            combined_queue = input(f"Please input Combined queue size (default {max_combined_queue}): ")
            if not combined_queue:
                combined_queue = max_combined_queue
            else:
                combined_queue = int(combined_queue)
                if combined_queue > max_combined_queue:
                    combined_queue = max_combined_queue
                elif combined_queue <= 0:
                    combined_queue = None
        else:
            combined_queue = None
        if rx_queue:
            config_dict['rx_queue'] = rx_queue
        if tx_queue:
            config_dict['tx_queue'] = tx_queue
        if other_queue:
            config_dict['other_queue'] = other_queue
        if combined_queue:
            config_dict['combined_queue'] = combined_queue
    except:
        print("Failed to get network queue parameters!")

    # 提示是否开启RPS/RFS, 并注明开启后网络性能会进一步提升, 但是会消耗大量的CPU资源, 建议除非网络性能有问题, 否则不要开启
    print("RPS/RFS can further improve network performance, but it consumes a lot of CPU resources. "
          "It is recommended not to enable it unless there is a problem with network performance.")
    rps_rfs = input("Do you want to enable RPS/RFS? (yes/no) ")
    if rps_rfs == 'yes':
        config_dict['rps_rfs'] = True
    else:
        config_dict['rps_rfs'] = False

    # 保存配置文件
    with open(CONFIG_FILE, 'w') as f:
        f.write(json.dumps(config_dict, indent=4))
    print("Configuration file saved.")


def load_config():
    """
    Load configuration file.
    :return:
    """
    # 配置文件路径相对与当前文件的路径
    if not os.path.exists(CONFIG_FILE):
        print('Configuration file not found!')
        sys.exit(1)
    with open(CONFIG_FILE, 'r') as f:
        config_dict = json.load(f)
    # 更新全局SYSTEM_CONFIG_DICT
    SYSTEM_CONFIG_DICT.update(config_dict)
    print("Configuration file loaded.")
    # 打印配置
    print("Configuration:")
    for key, value in config_dict.items():
        print(f"{key}: {value}")
    print()


if __name__ == '__main__':
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='Distribute network card IRQs across CPU cores.')

    # 创建一个互斥参数组
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('--smp_affinity', action='store_true', default=False,
                       help='Distribute network card IRQs across CPU cores.')
    group.add_argument('--rfs', action='store_true', default=False,
                       help='Distribute network card IRQs across RPS/RFS queues.')
    group.add_argument('--ring_buff', action='store_true', default=False,
                       help='Set ring buffer size for network card.')
    group.add_argument('--check', action='store_true', default=False,
                       help='Check server environment settings.')
    group.add_argument('--hold_kernel_version', action='store_true', default=False,
                       help='Hold the current kernel version.')
    group.add_argument('--all', action='store_true', default=False,
                       help='Run all functions.')
    group.add_argument('--auto_start', action='store_true', default=False,
                       help='Setup auto start service.')
    group.add_argument('--disable_rps_rfs', action='store_true', default=False,
                       help='Disable RPS/RFS for a given network interface card.')
    group.add_argument('--update_config', action='store_true', default=False,
                       help='Update configuration file.')
    group.add_argument('--performance', action='store_true', default=False,
                       help='Set CPU performance to maximum mode.')

    parser.add_argument('--dry-run', action='store_true',
                        help='Do not actually change anything, just show what would be done.')
    args = parser.parse_args()
    # 判断当前是否有root权限
    if os.geteuid() != 0:
        print('This script must be run as root!')
        sys.exit(1)

    # 判断是否安装了ethtool, 没有则安装
    if not check_installed('ethtool'):
        print('Installing ethtool...')
        run_cmd('apt-get install -y ethtool', assert_success=True)
    if not args.update_config:
        setup_config()
    else:
        setup_config(True)
        sys.exit(0)
    load_config()
    # 获取CPU核心数量
    cpu_count = os.cpu_count()
    # 读取/proc/cpuinfo文件，获取所有的CPU核心名称
    with open('/proc/cpuinfo', 'r') as f:
        cpu_info = f.read()
    # 使用正则表达式匹配所有的CPU核心名称
    cpu_names = re.findall(r'processor\s+:\s+(\d+)', cpu_info)
    if args.smp_affinity:
        set_irq_affinity(cpu_count, args.dry_run)
    elif args.performance:
        set_cpu_performance()
    elif args.rfs:
        set_rps_rfs(cpu_count, args.dry_run)
    elif args.ring_buff:
        set_ring_buff(args.dry_run)
    elif args.check:
        check_server_env()
    elif args.hold_kernel_version:
        hold_kernel_version()
    elif args.all:
        run_all(cpu_count)
    elif args.auto_start:
        setup_auto_start()
    elif args.disable_rps_rfs:
        disable_rps_rfs(None)
    else:
        parser.print_help()
