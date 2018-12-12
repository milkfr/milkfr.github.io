---
title: Brup Suite插件编写
description: 最近Burp Suite插件编写的一些记录
categories:
 - 渗透工具
tags:
 - Burp Suite
 - 渗透工具
---

### 0x00 说明
最近Burp Suite插件编写的一些记录

### 0x01 IDEA环境搭建
* 新建Java项目，选择SDK，一路next
* Burp Suite的Extender->APIs->Save interface files到src中，会新建burp文件夹
* Open Module Settings->Artifacts->+->JAR->From modules with dependencies...->改名->+->Module Ouput->选择output
* 新建BurpExtender.java文件，继承registerExtenderCallbacks，开始写内容，如果存在第三方包，在src目录边上建立lib目录，将jar放入（因为我不是专业写Java，对一些包管理不清楚，所以用这种方式）
* 写完以后打包jar包，Build->Build Artifacts
* Burp Suite的Extender导入jar包


### 0x02 编写Burp Suite插件的好处和难点
#### 好处
* Burp Suite本身方便
* 编写插件对过程可以对Burp Suite本身的设计和一些功能有更深的理解
* 个人不喜欢Burp Suite上很多的选项和内置的一些策略，因为不是很懂怎么使用和它的实现，所以自己写对应站点的插件好一些，同时写的加解密、编码和Session维持的代码可以复用

#### 编写时候的难点
* 使用到了Java图形化界面编写的功能，我对界面编写不懂，会造成很大困难
* 源码还是封闭的，API有些说明不是很理解，也需要对Burp的一些功能理解到位了才可以正确编写
* 因为只有用API生成jar包，生成后倒入插件才可以测试使用，调试只能通过输出，调试非常麻烦

### 0x03 API说明
使用Burp Suite的Extender编写插件需要用到它的API，它提供的API主要可以分为以下几类
* 必须使用到的API：`IBurpExtender`（必须继承的接口），`IBurpExtenderCallbacks`（主要功能接口，对接、注册其他各个模块），`IExtensionStateListener`(移除插件时的善后工作，可用可不用)
* 界面编写相关API：`IContextMenuFactory`，`IContextMenuInvocation`（这两个接口关于右键HTTP/S包显示的），`IMessageEditor`，`IMessageEditorController`（这两个接口创建的一个和Repeater的改包一样的文本编辑界面），`IMessageEditorTab`，`IMessageEditorTabFactory`（这两个接口创建类似Proxy下面显示HTTP/S包信息Tab），`ITab`，`ITextEditor`（这两个接口创建Proxy、Repeater一类的大Tab）
* 常用的包处理API：`ICookie`（Cookie编辑接口），`IExtensionHelpers`（简单编码和HTTP包、参数处理工具接口），`IRequestResponse`，`IHttpRequestResponsePersisted`，`IHttpRequestResponseWithMarkers`，`IHttpService`，`IParameter`，`IRequestInfo`，`IResponseInfo`，`IResponseKeywords`，`IResponseVaraitions`（以上这些接口都是Request、Response相关的包处理工具接口）
* Proxy、Scanner、Intruder相关API：`IProxyListener`，`IInterceptedProxyMessage`，`IIntruderAttack`，`IIntruderPayloadGenerator`，`IIntruderPayloadGeneratorFactory`，`IIntruderPayloadProcessor`，`IScanIssue`，`IScannerCheck`，`IScannerInsertionPoint`，`IScannerInsertionPointProvider`，`IScannerListener`，`IScanQueueItem`（这些接口根据名字对应相应的工具模块）
* 其他功能API：`IBurpCollaboratorClientContext`，`IBurpCollaboratorInteraction`（这两个接口用于外部服务器交互），`IHttpListener`（监听所有HTTP包），`IScopeChangeListener`（Burp作用域限定），`ISessionHandlingAction`（Project options中的Sessions设置接口），`ITempFile`（临时文件的Buffer缓存）
* 被弃用的API：`IMenuItemHandler`

### 0x04 部分个人插件编写心得
#### Debug麻烦的问题
Burp Suite插件需要编译成jar包，然后导入到Burp Suite中才可以运行使用，存在编写Debug比较麻烦的问题

使用`PrinWriter stdout = new PrintWriter(callbacks.getStdout(), true)`和`PrinWriter stderr = new PrintWriter(callbacks.getStderr(), true)`，通过callback的接口，可以像在命令行调试一样把信息输出到Burp Extender的Tab中查看

#### Java图形界面编写的问题
Burp插件很多是Java的`awt, swing`的图形界面编写，这些图形界面编写我是不了解的，以前没有写过，写的时候都是网上搜索，能用则用，其实现在图形界面编写比较少，Web较多，也不推荐专门去学，遇到不得已的情况下才编写图形界面，能不用则不用，想清楚需求，有一些图形界面编写的调试工具，可以方便开发

#### 功能区分
Project Options中的session handling rule可以满足大部分的编解码，Token绕过，改包时参数重签名重加密等方面的，没必要在Intruder和Scanner提供的接口中重新编写这些功能，考虑清楚需要

#### 靶机搭建
也是为了方便Debug，自己搭建靶机，写一些和实际需要相同的功能，在靶机上测试，方便调整

[vuln-web](https://github.com/milkfr/burp-extenders/tree/master/vuln-web)上有我自己搭的靶机

### 0x05 编写的部分常用插件
#### logger
* 官网例子改一改，分析Burp工具出入包的插件，捕获出入的HTTP/S
* 可以在使用中插件Scanner发出的Payload，用来收集或者补全
* 可以添加和删除重要的包到工具Tab中，方便查看
* [详细说明](https://milkfr.github.io/burp%20suite/2018/05/21/burp-extender-logger/)

#### session-handling-rule-csrf-token
* 在Burp发送请求前先请求一次页面中带有CSRF Token的接口，解析其中的CSRF Token，替换掉包中已经过期的信息，从而绕过CSRF Token的限制，提高扫描效果因CSRF Token造成的准确率下降
* 一般CSRF Token是中间件，因此可以从一个页面解析的Token可以在其他页面使用，当然也需要根据实际情况修改解析策略
* [详细说明](https://milkfr.github.io/burp%20suite/2018/05/21/burp-extender-session-handling-rule-csrf-token/)

#### session-handling-rule-sign
* 改包后重签名
* 需要知道签名的算法
* 在对参数进行修改之后，重新签名，避免签名问题导致的改包失效
* [详细说明](https://milkfr.github.io/burp%20suite/2018/05/21/burp-extender-session-handling-rule-sign/)

#### editor-tab-codec
* 在MessageEditorTab中对参数编解码（加解密）的插件
* 需要知道编解码（加解密）算法
* 在Proxy模块中查看解码（解密）信息
* 在Repeater中修改Payload值可以直接编码（加密）信息
* [详细说明](https://milkfr.github.io/burp%20suite/2018/05/21/burp-extender-editor-tab-codec/)

#### scanner-rule
* Scanner 扫描规则制定
* 可以定制Payload
* 可以定制Payload的插入点
* 可以定制Payload的编码修改
* 可以定制扫描结果的报告信息
* [详细说明](https://milkfr.github.io/burp%20suite/2018/05/21/burp-extender-scanner-rule/)
