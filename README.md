# PPPoE Simulator

PPPoE 认证模拟器，获取拨号客户端发来的用户名和密码。

## 运行
Windows: 

安装 [Npcap](https://nmap.org/npcap/) (程序自带安装包，检测到未安装时会提示安装)。

Linux: 

`sudo apt install libpcap`

## 编译

Windows: 

安装 [Npcap](https://nmap.org/npcap/) 后运行脚本:
```shell
build.cmd
```

Linux:
```shell
sudo apt-get install libpcap-dev
chmod +x ./build.sh
./build.sh
sudo ./bin/pppoe-sim
```
