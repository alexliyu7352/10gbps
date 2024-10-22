# 10Gbps server one-click optimization

This project is designed to optimize the performance of servers with 10Gbps or higher bandwidth by configuring various system and network settings. The script `oco.py` provides functionalities such as setting IRQ affinity, configuring RPS/RFS, adjusting ring buffer sizes, and more.

## Prerequisites

- Ubuntu 18.04 or higher
- Python 3.11 or higher
- Root privileges
- `ethtool` installed
- `cpufrequtils` installed (for setting CPU performance)

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/alexliyu7352/10gbps.git
    cd 10gbps
    ```

2. Install required packages:
    ```sh
    sudo apt-get install -y ethtool cpufrequtils
    ```

## Usage

Run the script with the desired options. Below are the available options:

- `--smp_affinity`: Distribute network card IRQs across CPU cores.
- `--rfs`: Distribute network card IRQs across RPS/RFS queues.
- `--ring_buff`: Set ring buffer size for network card.
- `--check`: Check server environment settings.
- `--hold_kernel_version`: Hold the current kernel version.
- `--all`: Run all functions.
- `--auto_start`: Setup auto start service.
- `--disable_rps_rfs`: Disable RPS/RFS for a given network interface card.
- `--update_config`: Update configuration file.
- `--performance`: Set CPU performance to maximum mode.
- `--dry-run`: Do not actually change anything, just show what would be done.

### Example

To set IRQ affinity and configure RPS/RFS:

```sh
sudo python3 oco.py --smp_affinity
sudo python3 oco.py --rfs
```

To run all functions:
```sh
sudo python3 oco.py --all
```

### Configuration

The script uses a configuration file irq_config.json to store settings. The configuration file is automatically created and updated as needed.

### License

This project is licensed under the MIT License.
