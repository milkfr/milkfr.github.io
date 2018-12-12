---
title: Burp Suite插件编写logger
description: 官网Logger Demo的拓展，收集包和Burp Scanner的Payload
categories:
 - 渗透工具
tags:
 - Burp Suite
 - 渗透工具
---

### 0x00 功能介绍
* 分析Burp工具出入包的插件，捕获出入的HTTP/S
* 可以在使用中插件Scanner发出的Payload，用来收集或者补全
* 可以添加和删除重要的包到工具Tab中，方便查看

### 0x01 编写需要
* 了解Burp Suite Extender API中的`ITab, IHttpListener, IMessageEditorController, IContextMenuFactory`编写方式
* 了解Java图形界面swing、awt中的`JTable, JMenu`等编写方式

### 0x02 详细使用
#### 范围限制
可以对Logger插件自动抓取的HTTP/S包的范围进行限制

在插件源代码中的`processHttpMessage`的可以对抓取工具和域进行限制
```
if (toolFlag != IBurpExtenderCallbacks.TOOL_REPEATER &&
    toolFlag != IBurpExtenderCallbacks.TOOL_INTRUDER &&
    toolFlag != IBurpExtenderCallbacks.TOOL_SCANNER) {
    return;
}

// only process responses
if (!filterMessageInfo(messageInfo)) {
    return;
}
```

可以对toolFlag进行判断和自己写`filterMessageInfo`函数

#### 自动抓取HTTP及其显示
![1](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-logger/1.png)

插件会自动捕获HTTP包（默认捕获Repeater、Intruder、Scanner工具发出的包）

在插件的Logger Tab中会显示Tool名和URL名，点击某行会显示这个包的Request、Response信息

可以通过这种方式抓取Scanner中的包，并收集它的Payload

#### 手动添加和删除Logger工具中的包
可以从Proxy中将包发往Logger的列表，也可以从Logger的列表中删除包，使Logger维持一个需要记录的列表信息

![2](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-logger/2.png)

![3](https://milkfr.github.io/assets/images/posts/2018-05-21-burp-extender-logger/3.png)