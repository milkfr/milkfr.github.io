---
title: masscan的一些原理探究
description: 面试被问到masscan的原理了，基本除了异步这个词一点不懂，补习一下
categories:
 - 安全开发 
tags:
 - 安全开发
---

### 0x00 官方提示
[masscan](https://github.com/robertdavidgraham/Masscan)，都是C语言代码，虽然我大学也写了4年C语言，虽然这个代码写的每个模块都很清楚，但是具体到某几行是真的不懂什么意思

全靠官方提示

> The file main.c contains the main() function, as you'd expect. It also contains the transmit_thread() and receive_thread() functions. These functions have been deliberately flattened and heavily commented so that you can read the design of the program simply by stepping line-by-line through each of these.

就是`main.c`直接写了代码结构，看入口函数`main()`和发送函数`transmit_thread()`和`receive_thread()`

然后介绍了两个原理`Randomization`和`C10 Scalability`

### 0x01 随机化地址扫描
```
for (i = 0; i < range; i++) {
    ip = pick(addresses, i);
    scan(ip);
}
```

如上代码，就是将地址混乱之后，再扫描

```
range = ip_count * port_count;
for (i = 0; i < range; i++) {
    x = encrypt(i);
    ip   = pick(addresses, x / port_count);
    port = pick(ports,     x % port_count);
    scan(ip, port);
}
```

算法大概就是这样

设计了一个加密算法，随机种子i，在`[1...range]`的区域内通过i来生成`[1...range]`内不重复的随机数

也可以用于分布式，根据i的值可以分配到不同机器上，不会重复

[加密算法](https://web.cs.ucdavis.edu/~rogaway/papers/subset.pdf)

### 0x02 C10k问题
masscan硬件性能足够如何处理超过1w的连接请求

> There are three primary kernel bypasses in Masscan:

> custom network driver

> user-mode TCP stack

> user-mode synchronization

也就是

#### 定制网络启动
默认模式下，masscan使用pcap发送和接受数据包，在Linux上可以达到150w/s，在window和mac上30w/s

如果使用了PF_RING DNA设备，它会提升到1000w/s发包速度

PF_RING DNA的驱动程序，可以直接从用户模式向网络驱动程序发送数据包而不经过系统内核

#### 用户模式的TCP栈
masscan有自己内置的TCP堆栈，用于从TCP连接种获取banner，意味着它可以轻松地支持1000w个并发TCP连接

#### 用户模式的同步
masscan没有互斥锁，现代的互斥锁大多是用户模式，会造成性能降低

使用了一个`rings`来进行同步，应该是masscan自己实现的一种机制，这个`rings`用在了打印到终端、输出到文件的过程中

如果是一张网卡，只会开启一个接受线程和一个发送线程，这两个线程不需要共享变量，但是如果有多个网卡，就要有多个线程发送和接受，在打印终端和输出文件中需要用`rings`来防止冲突

### 0x02 异步扫描原理
上面我们看完了masscan的README提示

####异步原理
接下来需要了解异步扫描的原理

TCP三次握手的过程

* 客户端发送SYN（SEQ=x）报文给服务器端，进入SYN_SEND状态。
* 服务器端收到SYN报文，回应一个SYN （SEQ=y）ACK（ACK=x+1）报文，进入SYN_RECV状态
* 客户端收到服务器端的SYN报文，回应一个ACK（ACK=y+1）报文，进入Established状态

一般情况下我们使用全连接扫描，发出SYN后都需要在监听返回，一台机器就算65536端口全部用上也不快

我们使用masscan时候就知道，我们退出扫描都时候，masscan都会停止10s再退出，这个时候masscan在接受数据包

也就是说，masscan不是通过端口到端口都连接进行扫描的

而是通过驱动不断对目标发包，服务器返回包经过驱动被接受，masscan根据返回包携带的信息判断来源的IP和端口

和我们编程语言中的异步一样，都是发出请求后，不再阻塞等待，而是接受到包之后，通知程序判断来源

#### 判断来源
判断来源我们首先要了解无状态扫描

我们修改一下上面的TCP三次握手

* 客户端第一次握手时，设置SEQ序列号为一个特殊数字，数字用特殊的算法生成，可以判断IP和端口
* 服务器收到包返回的时候返回的`ACK=(SYN+1)`
* 客户端收到返回包返回RST结束连接

关键就在于这个SEQ的生成

#### SEQ生成
一开始README已经提示我们发包要看`transmit_thread`函数了

结构很清晰，我们马上能找设置SEQ的地方

```
/*
 * SYN-COOKIE LOGIC
 *  Figure out the source IP/port, and the SYN cookie
 */
if (src_ip_mask > 1 || src_port_mask > 1) {
    uint64_t ck = syn_cookie((unsigned)(i+repeats),
                            (unsigned)((i+repeats)>>32),
                            (unsigned)xXx, (unsigned)(xXx>>32),
                            entropy);
    port_me = src_port + (ck & src_port_mask);
    ip_me = src_ip + ((ck>>16) & src_ip_mask);
} else {
    ip_me = src_ip;
    port_me = src_port;
}
cookie = syn_cookie(ip_them, port_them, ip_me, port_me, entropy);
```

设置完SYN-COOKIE后，下面就发包了

我们可以看到SYN Cookie是通过计算源IP，源端口，目的IP，目的端口和entropy（随机种子）

```
uint64_t
syn_cookie( unsigned ip_them, unsigned port_them,
            unsigned ip_me, unsigned port_me,
            uint64_t entropy)
{
    unsigned data[4];
    uint64_t x[2];

    x[0] = entropy;
    x[1] = entropy;

    data[0] = ip_them;
    data[1] = port_them;
    data[2] = ip_me;
    data[3] = port_me;
    return siphash24(data, sizeof(data), x);
}
```

使用了一个siphash24的hash算法

然后我们看看`receive_thread`是如何验证SYN-Cookie的

```
/* verify: syn-cookies */
if (cookie != seqno_me - 1) {
    LOG(5, "%u.%u.%u.%u - bad cookie: ackno=0x%08x expected=0x%08x\n",
        (ip_them>>24)&0xff, (ip_them>>16)&0xff,
        (ip_them>>8)&0xff, (ip_them>>0)&0xff,
        seqno_me-1, cookie);
    continue;
}
```

确实有一个减1的操作，证明是ACK的返回

这样我们就大致知道了原理

### 其他参考
[zmap的官方Paper](https://zmap.io/paper.pdf)，也写了一些原理，甚至包含美国网络反应率，上面也介绍了SYN-Cookie