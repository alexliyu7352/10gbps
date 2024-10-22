### 10Gbps服务器一键优化

此项目旨在通过配置各种系统和网络设置来优化具有10Gbps或更高带宽的服务器性能。脚本`oco.py`提供了设置IRQ亲和性、配置RPS/RFS、调整环形缓冲区大小等功能。

## 先决条件

- Ubuntu 18.04 或更高版本
- Python 3.11 或更高版本
- Root 权限
- 已安装 `ethtool`
- 已安装 `cpufrequtils`（用于设置 CPU 性能）

## 安装

1. 克隆仓库：
    ```sh
    git clone https://github.com/alexliyu7352/10gbps.git
    cd 10gbps
    ```

2. 安装所需软件包：
    ```sh
    sudo apt-get install -y ethtool cpufrequtils
    ```

## 使用方法

使用所需选项运行脚本。以下是可用选项：

- `--smp_affinity`：将网络卡 IRQ 分配到 CPU 核心。
- `--rfs`：将网络卡 IRQ 分配到 RPS/RFS 队列。
- `--ring_buff`：设置网络卡的环形缓冲区大小。
- `--check`：检查服务器环境设置。
- `--hold_kernel_version`：锁定当前内核版本。
- `--all`：运行所有功能。
- `--auto_start`：设置开机自启动服务。
- `--disable_rps_rfs`：禁用指定网络接口卡的 RPS/RFS。
- `--update_config`：更新配置文件。
- `--performance`：将 CPU 性能设置为最大模式。
- `--dry-run`：不实际更改任何内容，只显示将要执行的操作。

### 示例

设置 IRQ 亲和性和配置 RPS/RFS：

```sh
sudo python3 oco.py --smp_affinity
sudo python3 oco.py --rfs
```

运行所有功能：

```sh
sudo python3 oco.py --all
```

### 配置

脚本使用配置文件 irq_config.json 来存储设置。配置文件会根据需要自动创建和更新。


### 许可证

此项目根据 MIT 许可证授权。


