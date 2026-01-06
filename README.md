# SEULogin

SEULogin 是一个用于登录东南大学网络的工具。

SEULogin is a tool for logging into the Southeast University network.

## 功能 / Features

- 登录网络 / Login to the network
- 生成配置文件 / Generate configuration file
- 检查配置文件 / Check configuration file
- 转换配置文件格式 / Convert configuration file format
- 编辑配置文件 / Edit configuration file
- 管理网络连接 / Manage network connection
- 设置定时任务 / Set up cron jobs

## Roadmap

- [x] 使用 UPnP 获得路由器 IP 地址
- [x] 更好的日志系统和终端显示
- [ ] 搭配 DDNS 服务使用
    - [ ] cloudflare
    - [ ] alidns
    - [ ] dnspod

## 使用方法 / Usage

<details>

<summary>下载安装包并配置 / Download and install package and configure</summary>

### 下载安装包 / Download and install package

在 [Release](https://github.com/SmartFPGATutor/seulogin/releases) 页面下载对应平台的安装包。

Download the installation package for the corresponding platform from the [Release](https://github.com/SmartFPGATutor/seulogin/releases) page.

#### Systemd 服务安装 / Systemd service installation

安装 seulogin_amd64.deb 包 / Install the seulogin_amd64.deb package

```
# debian/ubuntu/linuxmint/zorin
sudo dpkg -i seulogin_amd64.deb
# centos/almalinux/rocky/rhel/fedora
sudo rpm -i seulogin_amd64.rpm
```

修改配置文件 / Modify the configuration file

```
sudo seulogin gen /etc/seulogin/config.toml
sudo nano /etc/seulogin/config.toml
```

启动服务 / Start the service

```
sudo systemctl start seulogin@config.toml
sudo systemctl enable seulogin@config.toml
```

#### 基于 RC 的安装 / Install based on RC

```
# alpine
apk add seulogin_amd64.apk
```

修改配置文件 / Modify the configuration file

```
seulogin gen /etc/seulogin/config.toml
seulogin edit /etc/seulogin/config.toml
```

启动服务 / Start the service

```
/etc/init.d/seulogin start config
```

自动启动 / Auto start

```
rc-update add seulogin@config
```
</details>

### 直接安装 / Install directly

```
go install github.com/SmartFPGATutor/seulogin@latest
```

### 使用 Docker 安装 / Install using Docker

<details>
<summary> Docker 的各种安装方法 / Various installation methods for Docker</summary>

```
docker pull nerdneils/seulogin:latest # dockerhub
docker pull ghcr.io/SmartFPGATutor/seulogin:latest # ghcr
```

#### 运行 / Run

```
docker run --network host -it -v ./config.toml:/etc/seulogin/config.toml nerdneils/seulogin:latest # dockerhub
docker run --network host -it -v ./config.toml:/etc/seulogin/config.toml ghcr.io/SmartFPGATutor/seulogin:latest # ghcr
```

> 注意: 需要将配置文件挂载到容器中。

> Note: The configuration file needs to be mounted to the container.

#### Docker-Compose

```yaml
services:
  seulogin:
    image: nerdneils/seulogin:latest # dockerhub
    #image: ghcr.io/SmartFPGATutor/seulogin:latest # ghcr
    volumes:
      - ./config.toml:/etc/seulogin/config.toml
    restart: always
    network_mode: host
    command: ["sh", "-c", "seulogin cron /etc/seulogin/config.toml"]
```

</details>

### 基本命令 / Basic Commands

```
seulogin [command]
```

可用的命令 / Available Commands:
- `version`: 显示版本信息 / Show version information
- `gen`: 生成配置文件 / Generate configuration file
- `check`: 检查配置文件 / Check configuration file
- `convert`: 转换配置文件格式 / Convert configuration file format
- `edit`: 编辑配置文件 / Edit configuration file
- `conn`: 测试网络连接 / Test network connection
- `login`: 使用配置文件登录（单次） / Login using configuration file (one-time)
- `cron`: 使用配置文件设置定时任务 / Set up cron jobs using configuration file
- `tui`: 启动交互式终端界面 / Launch interactive TUI

### TUI 使用 / TUI Usage

```
seulogin tui
```

交互式界面提供登录、网络检测、定时任务和状态页签。  
Use the TUI to manage login, network checks, cron, and status.

![TUI Screenshot](.github/images/tui.png)

### 登录 / Login

```
Use config file to login to seulogin

Usage:
  seulogin login [flags]

Flags:
  -c, --config string     config file
  -h, --help              help for login
  -i, --ip string         ip
  -p, --password string   password
  -r, --raw-ip            use raw ip of login server, not use domain name of login server
  -u, --username string   username

Global Flags:
  -v, --verbose   Enable verbose output
```

使用 `-c` 指定配置文件登录网络。也可以直接使用 `-u` `-p` `-i` `-r` 参数直接登录。

Login to the network using `-c` to specify the configuration file. You can also use `-u` `-p` `-i` `-r` parameters directly to login.


### 设置定时任务 / Set up cron jobs

```
seulogin cron [config_file_path]
```

使用指定的配置文件设置定时任务。在执行定时任务时，会先检测网络连接，如果网络连接正常，则不进行登录操作。否则，会使用配置文件中的信息登录网络。

配置文件中需要包含 `cron_exp` 字段，指定定时任务的执行周期。

Set up cron jobs using the specified configuration file. Before executing the cron job, it will check the network connection. If the network connection is normal, it will not perform the login operation. Otherwise, it will use the information in the configuration file to log in to the network.

The configuration file needs to contain the `cron_exp` field, which specifies the execution period of the cron job.

### 检查配置 / Check Configuration

```
seulogin check [config_file_path]
```

检查指定的配置文件是否有效。

Check if the specified configuration file is valid.

### 转换配置文件格式 / Convert Configuration File Format

```
seulogin convert [input_file_path] [output_file_path]
```

将配置文件从一种格式转换为另一种格式（TOML 到 JSON 或 JSON 到 TOML）。

Convert the configuration file from one format to another (TOML to JSON or JSON to TOML).

### 编辑配置文件 / Edit Configuration File

```
seulogin edit [config_file_path]
```

使用系统默认编辑器编辑指定的配置文件。(Win: notepad, Linux: xdg-open/$EDITOR/vim, macOS: open)

Edit the specified configuration file using the system's default editor. (Win: notepad, Linux: xdg-open/$EDITOR/vim, macOS: open)


### 测试网络连接 / Test Network Connection

```
seulogin conn
```

测试当前网络连接是否正常。

Test if the current network connection is normal.

具体来说，有下面的命令 / Specifically, there are the following commands:

- 默认(空命令): 测试连接到因特网的连接 / Default(empty command): test the connection to the Internet
- `login`: 测试到登录服务器的连接 / Test the connection to the login server
- `seulan`: 测试到东南大学校内局域网连接 / Test the connection to the Southeast University campus network
- `ping [ip/hostname]`: 测试到指定主机的连接 (使用 ICMP ping) / Test the connection to the specified host using ICMP ping
- `tcp [ip:port]`: 测试到指定主机的 TCP 连接 / Test the TCP connection to the specified host
- `http [url]`: 测试到指定 URL 的 HTTP 连接 / Test the HTTP connection to the specified URL

> 注意, `ping` 在 macOS 上没有实现，请使用系统自带的 `ping` 命令。

> Note: `ping` is not implemented on macOS, please use the system's `ping` command.


## 配置文件

<details>
<summary>TOML 配置文件示例 / TOML configuration file example</summary>

```toml
log_level = "info" # 日志级别 (debug, info, warn, error) / Log level (debug, info, warn, error)
cron_exp = "*/1 * * * *" # 每 1 分钟检查一次 (https://pkg.go.dev/github.com/robfig/cron/v3#hdr-CRON_Expression_Format) / Check every 1 minute (https://pkg.go.dev/github.com/robfig/cron/v3#hdr-CRON_Expression_Format)
retry_interval = 10 # 重试间隔时间，单位为秒 (秒) / Retry interval time, unit is seconds (seconds)
retry_times = 3 # 重试次数 / Retry times
log_file = "" # 日志文件路径(如果为空，则不保存到文件) / Log file path (if it is empty, it will not be saved to a file)

[[login_ip]] # 指定 IP 进行登录（可以有多个） / Specify IP for login (can have multiple)
ip = "10.0.0.1"
username = "username"
password = "password"
use_ip = true # 是否不解析登录节点域名，直接连接到登录节点的 IP (默认: true) / Whether to not resolve the login node domain name, directly connect to the login node's IP (default: true)

[[login_interface]] # 指定接口进行登录（可以有多个） / Specify interface for login (can have multiple)
interface = "eth0" # 将会自动获得接口的 IP 地址 / Will automatically get the interface's IP address
username = "username"
password = "password"
use_ip = true # 是否不解析登录节点域名，直接连接到登录节点的 IP (默认: true) / Whether to not resolve the login node domain name, directly connect to the login node's IP (default: true)

[[login_upnp]] # 指定 UPnP 接口进行登录（可以有多个） / Specify UPnP interface for login (can have multiple)
interface = "eth0" # 将会自动获得接口的 IP 地址 / Will automatically get the interface's IP address 
username = "username"
password = "password"
use_ip = true # 是否不解析登录节点域名，直接连接到登录节点的 IP (默认: true) / Whether to not resolve the login node domain name, directly connect to the login node's IP (default: true)
exclude=["10.0.0.1"] # 排除的 IP 地址列表(如果 UPnP 获得的 IP 地址在这个列表中，则不进行登录) / Exclude IP address list (if the IP address obtained from UPnP is in this list, it will not be logged in)
```
</details>


<details>
<summary>JSON 配置文件示例 / JSON configuration file example</summary>

```json
{
  "cron_exp": "*/1 * * * *",
  "retry_interval": 10,
  "retry_times": 3,
  "log_file": "",
  "log_level": "info",
  "login_ip": [
    {
      "ip": "10.0.0.1",
      "username": "username",
      "password": "password",
      "use_ip": true
    }
  ],
  "login_interface": [
    {
      "interface": "eth0",
      "username": "username",
      "password": "password",
      "use_ip": true
    }
  ],
  "login_upnp": [
    {
      "interface": "eth0",
      "username": "username",
      "password": "password",
      "use_ip": true,
      "exclude": [
        "10.0.0.1"
      ]
    }
  ]
}
```
</details>


## 选项 / Options

- `-v, --verbose`: 启用详细输出 / Enable verbose output

## 版本信息 / Version Information

使用 `seulogin version` 命令可以查看详细的版本信息，包括构建时间和 Git 提交哈希。

Use the `seulogin version` command to view detailed version information, including build time and Git commit hash.

## 作为库使用 / As a library

可以作为库导入到项目中使用。 `import "github.com/SmartFPGATutor/seulogin/pkg/seulogin"`, 你可以方便地使用其中的函数来实现你的需求。

Import it into your project as a library. `import "github.com/SmartFPGATutor/seulogin/pkg/seulogin"`, you can easily use the functions in it to implement your needs.

## 贡献 / Contributing

欢迎提交问题和拉取请求。

Issues and pull requests are welcome.

## 许可证 / License

```
MIT License

Copyright (c) 2024 Qi Deng <dengqi@shanghaitech.edu.cn> <dengqi935@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=SmartFPGATutor/seulogin&type=Date)](https://star-history.com/#SmartFPGATutor/seulogin&Date)
