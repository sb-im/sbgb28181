# 基于ZLmediaKit和wvp-GB28181-pro的GB28181视频监控平台
这个平台可以测试GB28181的多种流传输模式：UDP、TCP主动、TCP被动。

这套系统对协议比较宽松，有的比较严格，比如基于GoSIP的，要求视频流的ssrc必须一致才接收。

还可以使用SRS来搭建，参考https://ossrs.net/lts/zh-cn/docs/v7/doc/gb28181

需要重新编译，不能用编译好的docker，它只支持TCP传输，也很宽松。

还有这款也可以测试https://github.com/gowvp/gb28181


## 安装依赖
```bash
apt-get update
apt-get install cmake gcc openssl git libssl-dev build-essential ffmpeg redis
# 安装libsrtp
cd ~
curl -LO https://github.com/cisco/libsrtp/archive/refs/tags/v2.5.0.tar.gz
tar -zxvf v2.5.0.tar.gz
cd libsrtp-2.5.0
./configure
make && sudo make install
```

## 编译ZLMeidaKit
```bash
cd ~
git clone --depth 1 https://github.com/ZLMediaKit/ZLMediaKit
#国内可用 git clone --depth 1 https://gitee.com/xia-chu/ZLMediaKit
cd ZLMediaKit
git submodule update --init
mkdir build
cd build
cmake ..
make -j
#配置并运行
cd ~/ZLMediaKit/release/linux/Debug
vim config.ini
# 公网部署时,将http.allow_ip_range的值留空
# 复制api.secret的值
# 修改general.mediaServerId的值为sbgb28181test
./MediaServer
```

## 安装node
```bash
cd ~
wget https://npm.taobao.org/mirrors/node/v14.17.2/node-v14.17.2-linux-x64.tar.xz
tar -xvf node-v14.17.2-linux-x64.tar.xz
mv node-v14.17.2-linux-x64 /usr/local/nodejs
ln -s /usr/local/nodejs/bin/node /usr/bin/node
ln -s /usr/local/nodejs/bin/npm /usr/local/bin
# 国内镜像 npm config set registry https://registry.npmmirror.com
npm config list
#验证
node -v
npm -v
```

## 安装jdk
```bash
cd /home
sudo apt install openjdk-11-jre
#验证
java --version
```

## 安装maven
```bash
cd ~
wget https://archive.apache.org/dist/maven/maven-3/3.8.4/binaries/apache-maven-3.8.4-bin.tar.gz
tar -xvf apache-maven-3.8.4-bin.tar.gz
mkdir /usr/local/maven
mv apache-maven-3.8.4 /usr/local/maven/apache-maven-3.8.4
#配置环境变量
vim /etc/profile
MAVEN_HOME=/usr/local/maven/apache-maven-3.8.4
export PATH=${MAVEN_HOME}/bin:${PATH}
#刷新文件
source /etc/profile
#验证
mvn –v
```



## 安装wvp-GB28181-pro
```bash
cd ~
git clone https://github.com/648540858/wvp-GB28181-pro
# 国内可用git clone https://gitee.com/pan648540858/wvp-GB28181-pro.git
#编译静态页面
cd ~/wvp-GB28181-pro/web_src/
npm --registry=https://registry.npmmirror.com install
npm run build
#编译完成后在src/main/resources下出现static目录
#打包项目, 生成可执行jar
cd ..
mvn package
```



## 安装mysql8并导入数据
```bash
cd ~
sudo apt-get install mysql-server
#设置密码
mysql -u root -p
mysql> use mysql ;
mysql> UPDATE user SET host = '%' WHERE user ='root';
mysql> FLUSH PRIVILEGES;
mysql> ALTER USER 'root'@'%' IDENTIFIED WITH mysql_native_password BY 'NEW_PASSWORD';    #NEW_PASSWORD  修改成你的密码。
mysql> FLUSH PRIVILEGES;
mysql> exit;

cd ~/wvp-GB28181-pro/数据库/2.7.0/
mysql -u root -p
mysql> CREATE DATABASE wvp;
mysql> use wvp;
mysql> source 初始化-mysql-2.7.0.sql;
mysql> exit;
```

## 修改WVP配置文件
```bash
cd ~/wvp-GB28181-pro/src/main/resources
mv all-application.yml ../../../target/
cd ../../../target/
vim all-application.yml
#修改datasource.password为mysql的root密码
#修改sip.ip填写0.0.0.0
#修改media.id为sbgb28181test
#media.secret填写在zlm中复制的api.secret的值
#media.ip和media.hook-ip填写服务器内网ip
#media.stream-ip和media.sdp-ip填写服务器公网ip
```

## 启动WVP
```bash
java -jar wvp-pro-2.7.0-05070545.jar --spring.config.location=application.yml
```
打开浏览器
http://xxx.xxx.xxx.xxx:18080/
输入默认用户名和密码admin
