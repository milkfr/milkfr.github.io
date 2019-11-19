---
title: 开发环境搭建
description: 我的开发环境搭建
categories:
 - 环境搭建
tags:
 - 环境搭建
---

### Ubuntu虚拟机
VMWare安装Ubuntu虚拟机器作为开发环境

安装时使用简体中文安装，可以跳过对输入法的软件安装

安装vmware-tools

修改apt源为[清华源](https://mirror.tuna.tsinghua.edu.cn/help/ubuntu/)

```
# 更新源和升级软件
$ sudo apt-get update
$ sudo apt-get upgrade
```

搜索Chrome安装Chrome

### 常用软件安装
#### 常用
```
$ sudo apt-get install vim  # 安装vim
$ sudo apt-get install git  # 安装git
$ $ git config --global alias.lg "log --color --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit"  # git log美化
```

#### zsh
根据[Installing-ZSH](https://github.com/robbyrussell/oh-my-zsh/wiki/Installing-ZSH)的说明安装zsh，并将默认shell切换为zsh

根据oh-my-zsh的[README](https://github.com/robbyrussell/oh-my-zsh)的说明安张oh-my-zsh

修改`.zshrc`的`ZSH_THEME`变量为`ys`，修改主题

重新打开shell

#### MySQL
根据[文档说明](https://dev.mysql.com/doc/mysql-apt-repo-quick-guide/en/)添加MySQL8的apt源，再通过`sudo apt-get install mysql-server`安装，中间会提示设置root密码

修改MySQL编码为UTF8MB4，在`/etc/mysql/my.cnf`中添加以下内容

```
[mysqld]
character-set-server=UTF8MB4
[client]
default-character-set=UTF8MB4
```

重启服务`sudo mysql service restart`

校验编码是否改变

```
$ mysql -u root -p

mysql> show variables like '%character%';
+--------------------------+--------------------------------+
| Variable_name            | Value                          |
+--------------------------+--------------------------------+
| character_set_client     | utf8mb4                        |
| character_set_connection | utf8mb4                        |
| character_set_database   | utf8mb4                        |
| character_set_filesystem | binary                         |
| character_set_results    | utf8mb4                        |
| character_set_server     | utf8mb4                        |
| character_set_system     | utf8                           |
| character_sets_dir       | /usr/share/mysql-8.0/charsets/ |
+--------------------------+--------------------------------+
```

#### redis
简单安装即可`sudo apt-get install redis`

修改`/etc/redis/redis.conf`，添加`requirepass`

重启服务`sudo service redis restart`

校验`requirepass`是否生效

```
$ redis-cli
127.0.0.1:6379> set 122 333
(error) NOAUTH Authentication required.
```

### nginx
根据[官方文档](http://nginx.org/en/linux_packages.html#Ubuntu)安装nginx

删除`/etc/nginx/conf.d/default.conf`

#### jetbrains全家桶
官网安装ToolBox，傻瓜安装，我觉得它家产品真好

#### pyenv
根据[README](https://github.com/pyenv/pyenv)安装pyenv

`pyenv install`的速度很慢，可以新建文件夹`~/.pyenv/cache`，从Python官网下载好对应版本的`tar.xz`文件，放在这个目录中，就不用下载可以直接安装

安装过程中容易出现缺少依赖，安装：`sudo apt-get install gcc build-essential zlib1g-dev libbz2-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev`  

根据[README](https://github.com/pyenv/pyenv-virtualenv)安装pyenv-virtualenv

主要这样使用

```
$ pyenv install 3.8.0
$ pyenv virtualenv 3.8.0 venv
$ pyenv local venv
$ pyenv activate venv
```

#### nvm
根据[README](https://github.com/nvm-sh/nvm)安装nvm

和pyenv一样，如果下载版本太慢，可以从官网下载后放到下载时提示的目录下

主要这样使用

```
$ nvm install 10.15.3
$ nvm use 10.15.3
$ npm config set registry https://registry.npm.taobao.org  # npm改淘宝镜像
```

#### Java
创建javaenv目录

[官网](https://www.oracle.com/technetwork/java/javase/downloads/index.html)下载JDK解压后放到javaenv目录下

配置Java环境变量
```
export JAVA_HOME=~/javaenv/jdk1.8.0_231
export CLASSPATH=.:$JAVA_HOME/jre/lib/rt.jar:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib/tools.jar
export PATH=$JAVA_HOME/bin:$PATH
```

重启shell后通过`java -version`和`javac -version`验证


[官网](https://tomcat.apache.org/)下载Tomcat解压后放到javaenv目录下

编辑`path/conf/server.xml`，在`Connector`最后添加`URLEncoding=“UTF-8“`属性

运行`path/startup.sh`，访问本机8080端口可访问到管理台

#### docker
根据[官方文档](https://docs.docker.com/install/linux/docker-ce/ubuntu/)安装docker

根据[中科大源说明](https://lug.ustc.edu.cn/wiki/mirrors/help/docker)修改镜像地址

重启docker`$ sudo service docker restart`，校验`$ sudo docker run hello-world`，如果不成功，可以修改上一条中的镜像地址为其他镜像地址尝试

根据[说明](http://get.daocloud.io/#install-compose)，用root权限安张docker-compose
