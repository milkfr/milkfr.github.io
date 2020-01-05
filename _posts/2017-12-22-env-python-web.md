---
title: Python Web一些常用部署过程
description: 记录Python的Web应用部署过程中常用的一些组件，app本身、gunicorn、supervisor、nginx、前端等
categories:
 - 环境搭建
tags:
 - 环境搭建
---

### 0x00 一个Python Web项目的大致模块划分
我自己的web项目，大致分成（一些和部署无关的模块隐藏）

```
- app  # flask app
    - app  # web后台的内容
    - master  # celery 任务调度的任务分配节点（处理任务初始化和回调）
    - node  # 具体任务调度执行的节点
    - manager.py  # web后台的管理器，wsgi的载体
    - celery_worker.py  # celery的管理器
    - .env  # 一些敏感的配置参数，输入到环境变量中，部署在不同位置不同，比如node节点不需要访问web后台的数据库
    - gunicorn.py  # gunicorn的配置
- manager  # 前端vue
    - .env  # vue的环境变量配置
- supervisor.d  # supervisor的配置
- nginx.conf  # nginx的配置
```

### 0x01 web app/gunicorn本身的部署
我常用flask，这里以flask为例子，开发的使用使用的pyenv-virtualenv，生产部署也可以使用或者直接用`python -n venv`，只要有一个虚拟环境就可以

维护一份requirements.txt，以前会使用pipenv，但是安装依赖慢，老是出问题，就算了，自己维护，开发时候添加什么库加上去

修改.env中的各种配置

配置gunicorn.py

```
import multiprocessing

# 工作模式
worker_class = 'gevent'

# 并行工作进程数
workers = 4  # multiprocessing.cpu_count()

# 指定每个工作者的线程数
# threads = 2

# 监听地址
bind = '127.0.0.1:5000'

# 设置守护进程
daemon = 'false'

# 设置最大并发量
worker_connections = 10000

# 设置进程文件目录
# pidfile = '/var/run/gunicorn.pid'

# 设置访问日志和错误日志路径
accesslog = './gunicorn_access.log'
errorlog = './gunicorn_error.log'

# 设置日志记录水平
loglevel = 'warning'

# preload_app = True

```

我自己使用的是这一份配置，可以在[gunicorn文档](http://docs.gunicorn.org/en/stable/)中寻找需要的参数

运行

```
# 不管用什么工具，切换的venv，这里省略
$ pip install -r requirements.txt
# 初始化flask环境，deploy，数据库创建等操作，这里省略
$ guncorn -c gunicorn.py manager:app
```

这里注意部署时候是nginx对外转发，所以监听端口还是对内

### 0x02 celery
如有需要celery的master和node节点的requirements也需要单独维护，配置也需要单独改

```
# 不管用什么工具，切换的venv，这里省略
$ pip install -r requirements.txt
# celery如果有什么需要初始化的环境，或者依赖的flask需要，也deploy一下
$ celery -A celery_worker.celery worker -B -l INFO -Q master -n master  # 开启master节点，因为是配置了路由和节点名为master，所以加了-Q和-n参数，-B是因为有定时任务
$ celery -A celery_worker.celery worker -l INFO -Q node -n node  # 开启node节点，同样配置了路由和节点名为node，所以加了-Q和-n参数
$ celery flower -A celery_worker.celery --basic-auth=username:password  # 配置celery flower，默认为555端口，可以配置，注意设置用户名和密码，url前缀方便nginx配置
```

celery和celery-flower可以到他们到官方文档中查看，还有很多配置，celery-flower还描述了nginx如何配置

### 0x03 前端vue
修改.env的配置信息，在开发环境本地编译

```
$ npm run build
```

将生成的dist文件部署到nginx部署的对应目录下，之后通过nginx的配置来进行操作就可以了

### 0x04 nginx
```
server {
    listen       8000;
    server_name  localhost;
    index index.html;
    root /Users/milkfr/ATField/manager/dist;
    location ^~ /celery/ {
        rewrite ^/celery/(.*)$ /$1 break;
        proxy_pass http://127.0.0.1:5555;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    location ^~ /api {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

这里配置了前端、app和celery-flower的重定向，其他可以根据nginx的配置按需增加

### 0x05 supervisor
可以使用supervisor进行进程管理

#### app进程

```
[program:atfield_app]
command=/Users/milkfr/.pyenv/versions/3.8.0/envs/atfield-master-venv/bin/gunicorn -c gunicorn.py manager:app      ; the program (relative uses PATH, can take args)
;process_name=%(program_name)s ; process_name expr (default %(program_name)s)
;numprocs=1                    ; number of processes copies to start (def 1)
directory=/Users/milkfr/ATField/master                ; directory to cwd to before exec (def no cwd)
;priority=999                  ; the relative start priority (default 999)
autostart=true                ; start at supervisord start (default: true)
startsecs=1                   ; # of secs prog must stay up to be running (def. 1)
startretries=3                ; max # of serial start failures when starting (default 3)
autorestart=unexpected        ; when to restart if exited after running (def: unexpected)
user=milkfr                   ; setuid to this UNIX account to run the program
;redirect_stderr=true          ; redirect proc stderr to stdout (default false)
stdout_logfile=/Users/milkfr/ATField/master/app.log         ; stdout log path, NONE for none 
;stdout_logfile_maxbytes=50MB   ; max # logfile bytes b4 rotation (default 50MB)
;stdout_logfile_backups=10     ; # of stdout logfile backups (0 means none, default 10)
;environment=A="1",B="2"       ; process environment additions (def no adds)
```

#### flower进程
```
[program:celery_flower]
command=/Users/milkfr/.pyenv/versions/3.8.0/envs/atfield-master-venv/bin/celery flower -A celery_worker.celery --basic_auth=username:password --url_prefix=celery   ; the program (relative uses PATH, can take args)
;process_name=%(program_name)s ; process_name expr (default %(program_name)s)
;numprocs=1                    ; number of processes copies to start (def 1)
directory=/Users/milkfr/ATField/master                ; directory to cwd to before exec (def no cwd)
;priority=999                  ; the relative start priority (default 999)
autostart=true                ; start at supervisord start (default: true)
startsecs=1                   ; # of secs prog must stay up to be running (def. 1)
startretries=3                ; max # of serial start failures when starting (default 3)
autorestart=unexpected        ; when to restart if exited after running (def: unexpected)
user=milkfr                   ; setuid to this UNIX account to run the program
;redirect_stderr=true          ; redirect proc stderr to stdout (default false)
stdout_logfile=/Users/milkfr/ATField/master/celery_flower.log         ; stdout log path, NONE for none 
;stdout_logfile_maxbytes=50MB   ; max # logfile bytes b4 rotation (default 50MB)
;stdout_logfile_backups=10     ; # of stdout logfile backups (0 means none, default 10)
;environment=A="1",B="2"       ; process environment additions (def no adds)
```

#### master进程
```
[program:celery_master]
command=/Users/milkfr/.pyenv/versions/3.8.0/envs/atfield-master-venv/bin/celery -A celery_worker.celery worker -B -l INFO -Q master -n master      ; the program (relative uses PATH, can take args)
;process_name=%(program_name)s ; process_name expr (default %(program_name)s)
;numprocs=1                    ; number of processes copies to start (def 1)
directory=/Users/milkfr/ATField/master                ; directory to cwd to before exec (def no cwd)
;priority=999                  ; the relative start priority (default 999)
autostart=true                ; start at supervisord start (default: true)
startsecs=1                   ; # of secs prog must stay up to be running (def. 1)
startretries=3                ; max # of serial start failures when starting (default 3)
autorestart=unexpected        ; when to restart if exited after running (def: unexpected)
user=milkfr                   ; setuid to this UNIX account to run the program
;redirect_stderr=true          ; redirect proc stderr to stdout (default false)
stdout_logfile=/Users/milkfr/ATField/master/celery_master.log         ; stdout log path, NONE for none 
;stdout_logfile_maxbytes=50MB   ; max # logfile bytes b4 rotation (default 50MB)
;stdout_logfile_backups=10     ; # of stdout logfile backups (0 means none, default 10)
;environment=A="1",B="2"       ; process environment additions (def no adds)
```

#### node进程
```
[program:celery_node]
command=/Users/milkfr/.pyenv/versions/3.8.0/envs/atfield-master-venv/bin/celery -A celery_worker.celery worker -l INFO -Q node -n node      ; the program (relative uses PATH, can take args)
;process_name=%(program_name)s ; process_name expr (default %(program_name)s)
;numprocs=1                    ; number of processes copies to start (def 1)
directory=/Users/milkfr/ATField/master                ; directory to cwd to before exec (def no cwd)
;priority=999                  ; the relative start priority (default 999)
autostart=true                ; start at supervisord start (default: true)
startsecs=1                   ; # of secs prog must stay up to be running (def. 1)
startretries=3                ; max # of serial start failures when starting (default 3)
autorestart=unexpected        ; when to restart if exited after running (def: unexpected)
user=milkfr                   ; setuid to this UNIX account to run the program
;redirect_stderr=true          ; redirect proc stderr to stdout (default false)
stdout_logfile=/Users/milkfr/ATField/master/celery_node.log         ; stdout log path, NONE for none 
;stdout_logfile_maxbytes=50MB   ; max # logfile bytes b4 rotation (default 50MB)
;stdout_logfile_backups=10     ; # of stdout logfile backups (0 means none, default 10)
;environment=A="1",B="2"       ; process environment additions (def no adds)
```
