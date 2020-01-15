---
title: Java反序列化漏洞的一些gadget
description: 记录一些自己学习过的gadget，和看过的一些比较好的资料，会不断更新
categories:
 - 漏洞分析
tags:
 - 漏洞分析
---

首先说一下学习gadget的感受

首先是要理解利用的这个库到底是做什么用的，有什么API，参数大概是怎么样的，有能力的看文档或者源码去研究，看网络文章辅助，除非文章确实写的好

然后看网络上文章的话有些不是很容易利用的利用链的话虽然有很多文章分析，但是可能还是看不懂，以我的经验，主要原因是这条gadget上使用到了设计模式，写文章的人也不一定懂，因为做安全的很少搞设计模式这些，所以模模糊糊，debug走到底了就完事了，如果不是很理解话建议请教开发，或者不知道什么设计模式可以搜索类名之类的，Java设计模式用的类名很多很接近，可能理解这里的设计模式这块代码就理解了

看网络文章还有一个问题是存在不能复现的情况，多数是因为Java版本的问题，随着版本更新，一些不安全的地方改进了，或者某些配置设置成默认安全的，所以容易导致环境复现不成功，非常影响学习，可以查查版本的问题，多切换环境，推荐[jenv](http://www.jenv.be/)

debug时候有一个问题是可能找不到bytecode，不能通过IDE到下一步执行代码的地方，我咨询过几个我们公司的Java开发，他们也不知道怎么解决，我这里建议不要怂，就是单步调试，几千下以后可能就跳到了你想要的下一个调用处

还有，就是如果看了很多还是看不懂，就是可以先学会利用了，然后先放着不管，可能看其他几条链，或者哪天有个牛逼的人写了篇好文章，或者之后学习了Java，对一些基础更加理解了，再回过头来看会舒服很多

最后，就是理解了以后，为了行动力，还是要建立工具链，[marshalsec](https://github.com/mbechler/marshalsec)和[ysoserial](https://github.com/frohoff/ysoserial)也要用起来，然后他们的Payload生成的源码也可以看看

### 0x00 URLDNS
以前学反序列化漏洞的时候写过，[如何理解Java反序列化漏洞](https://milkfr.github.io/%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/2018/12/01/analysis-java-deserialize/)，文章里分析简单的反序列化漏洞gadget就是分析的URLDNS

主要有`readObject`的地方就有，不要依赖包，可以方便检测

### 0x01 Commons Collections
以前为了加深反序列化漏洞印象写过，分析了ysoserial中Commons Collections 1，[Apache Commons Collections 3.1反序列化漏洞分析](https://milkfr.github.io/%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/2018/12/10/analysis-java-deserialize-commonscollections1/)

只分析了一种，其他可以看平安银行应用安全团队的这篇文章，[玩转Ysoserial-CommonsCollection的七种利用方式分析](https://www.freebuf.com/articles/web/214096.html)

### 0x02 RMI的codebase任意代码执行
RMI全称Remote Method Invocation，远程方法调用，名字看和RPC一样，是Java独有的机制，是让某个Java虚拟机上对象调用另一个Java虚拟机上对象的方法

也是Payload中常用的，经常被JNDI利用链中使用到

这个学习主要是RMI本身的一些机制和codebase任意代码执行

推荐P师傅[代码审计知识星球](https://t.zsxq.com/762fIaA)里面有一个Java安全漫谈，其中4、5、6三篇讲的是RMI

说一下我试了好几天，没有成功复现里面的例子，用别的文章里的例子复现了一下，debug看了看，但是P师傅文章里的讲的很详细，包括用wireshark对协议简单分析的过程，看得很清晰

简单讲一下就是，RMI客户端和服务端之间传递的是一些序列化之后的对象，反序列化的时候回去寻找类，如果某一端反序列化时发现一个对象，就会自己去CLASSPATH下寻找对应的类，如果没有找到，就回去远程加载codebase中的类

主要是通过控制codebase来导致命令执行漏洞

当然，因为高一些版本官方做了处理，需要满足`SecurityManager`和`java.rmi.server.useCodebaseOnly`的条件，利用起来就比较难了，会变得鸡肋

### 0x03 JNDI
JNDI（Java Naming and Directory Interface,Java命名和目录接口）是一种Java的API，它允许客户端通过name发现和查找数据和对象

这些对象可以存储在不同的命名或者目录服务中，例如RMI（远程方法调用），LDAP（轻型目录访问协议）等

我之前分析fastjson反序列化的开头，先分析了RMI-JNDI这条链，[fastjson反序列化漏洞分析](https://milkfr.github.io/%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/2019/07/22/analysis-java-deserialize-fastjson/)

[JNDI注入原理及利用](https://xz.aliyun.com/t/6633)：这篇介绍了RMI-JNDI和LDAP-JNDI两条链

### 0x04 LDAP
我从来没用过LDAP，先看看文章，之后有空实践了回来写心得

LDAP（Lightweight Directory Access Protocol）：即轻量级目录访问协议，是一种运行于TCP/IP之上的在线目录访问协议，主要用于目录中资源的搜索和查询

这里有两个问题

一个是注入，看这篇[LDAP注入与防御剖析](https://wooyun.js.org/drops/LDAP%E6%B3%A8%E5%85%A5%E4%B8%8E%E9%98%B2%E5%BE%A1%E5%89%96%E6%9E%90.html)

一个是和JNDI配合的反序列化，可以通过LDAP URL获取一些Factory类，执行造成反序列化漏洞，看这篇[Java中RMI、JNDI、LDAP、JRMP、JMX、JMS那些事儿（上）](https://paper.seebug.org/1091/)

### 0x05 JDK7u21
这个gadgets能利用的版本少，除了学习也不会用它写PoC

而且理解起来不容易，比新手杀手的Commons Collections还麻烦，PoC要构筑的条件也多，理解一下就好

可以看下面这两篇文章

[Java 反序列化漏洞始末（2）— JDK](https://bithack.io/forum/441)

[JDK反序列化Gadgets 7u21](https://xz.aliyun.com/t/6884)