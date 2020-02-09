---
title: 扫描器里的动态爬虫的一些实践（一）
description: 根据猪猪侠在先知白帽大会的PPT写的爬虫，实践过一段时间后的心得体会
categories:
 - 安全开发 
tags:
 - 安全开发
---

### 0x00 扫描器里的爬虫
#### 目标是什么
显然，用requests当爬虫，bs4解析，对现在前端是不行的，动态爬虫越来越重要

实际上我到现在还没懂猪猪侠的启发式爬虫是什么意思，叫做动态爬虫更好吧，其实还是把静态页面分析，改成动态操作js，增加加载，模拟点击和表单自动填写，然后对各种个例的特殊情况做分析，改善js hook的规则

最终目的是hook所有网络请求的接口，爬取更多的CGI请求

怎么hook

* 期望在页面加载之前注入一段js代码hook、备份各种未被污染的函数
* 期望在页面加载之后注入一段js代码遍历各个元素、触发各种事件、劫取各种CGI请求和返回

#### 我们要学习的一些基础
BOM(Browser Object Model)和DOM(Document Object Model)

可以看这篇博客[BOM和DOM详解](https://www.cnblogs.com/wangxiang9528/p/9855358.html)

简单来说就是DOM就是html标签解析的各种节点并被js加载成为的对象，就是处理HTML标签的对象

BOM是主要处理浏览器窗口的框架，就是打开chrome开发这工具，console里的window等对象

CDP(Chrome DevTools Protocol)，因为我们使用Chrome Headless作为模拟浏览器进行爬取工作

CDP可以看[文档](https://chromedevtools.github.io/devtools-protocol/)，可以看作Chrome等远程调试接口

[Puppeteer](https://zhaoqize.github.io/puppeteer-api-zh_CN/)是Chrome官方的Node库，提供高级API来通过DevTools控制Chromium或Chrome，默认用headless模式运行

#### 主要需要攻克的技术点
* 怎么定义页面加载的前与后
* 怎么注入js
* 注入js执行哪些功能

#### 我们使用到一些编程技术
主要是操作模拟浏览器的Chrome Headless，又因为我写扫描器的多用Python开发，而且node不会写，所以需要了解Python怎么操作chrome headless

* [pychrome（Python操作CDP）](https://github.com/fate0/pychrome)
* [pyppeteer（Python版的Puppeteer库）](https://github.com/miyakogi/pyppeteer)

我最开始接触的是pyppeteer因为猪猪侠在先知的PPT[WEB2.0启发式爬虫实战](https://xzfile.aliyuncs.com/upload/zcon/2018/11_WEB2.0%E5%90%AF%E5%8F%91%E5%BC%8F%E7%88%AC%E8%99%AB%E5%AE%9E%E6%88%98_%E7%8C%AA%E7%8C%AA%E4%BE%A0.pdf)

后来慢慢了解CDP，就慢慢学会直接操作CDP，就了解到了pychrome，缺点是两个都不是官方的，维护没有保证，优点是都可以用

重点还是要了解CDP的接口

### 0x01 页面加载前后的区分
#### 启动一下CDP
我们使用pyppeteer的时候它会打开浏览器，但是一般我们在服务器上部署headless的chrome

```
$ google-chrome --remote-debugging-port=9222 --headless --disable-gpu
```

pychrome提供了docker启动的方式

```
$ docker pull fate0/headless-chrome
$ docker run -it --rm --cap-add=SYS_ADMIN -p9222:9222 fate0/headless-chrome

DevTools listening on ws://0.0.0.0:9222/devtools/browser/30261dd5-e97c-47d1-b3e1-0195bdff536c
```

启动后会出现上面的`listening on`，这个在pyppeteer上有用

#### 页面加载的一些阶段
这部分主要参考了[爬虫 JavaScript 篇](https://paper.seebug.org/570/)

我们首先看看页面加载有几个阶段

先ping一下baidu

```
import pychrome
import pychrome.exceptions


# 监听事件生命周期的阶段
def lifecycle_event(**kwargs):
    print("{}: {}".format(kwargs['timestamp'], kwargs['name']))


# 打开CDP浏览器
browser = pychrome.Browser(url='http://127.0.0.1:9222')
# 打开一个新标签
tab = browser.new_tab()
# 设置页面监听事件生命周期的阶段
tab.Page.lifecycleEvent = lifecycle_event
# 使用tab和page
tab.start()
tab.Page.enable()
try:
    # 设置监听器可用
    tab.Page.setLifecycleEventsEnabled(enabled=True)
except pychrome.exceptions.CallMethodException:
    pass
# 定向到baidu
tab.Page.navigate(url="https://www.baidu.com")
tab.wait(60)
```

查看输出

```
241629.600416: commit
241629.600472: DOMContentLoaded
241629.60059: load
241629.600731: networkAlmostIdle
241629.600731: networkIdle
241629.600731: networkAlmostIdle
241629.600731: networkIdle
241669.66635: load
241669.666721: DOMContentLoaded
241669.666743: networkAlmostIdle
241669.666743: networkIdle
```

commit应该是发出请求，这里不管，我们看看剩下4个是什么意思

* DOMContentLoaded：一般表示DOM和CSSOM均准备就绪的时间点
* networkAlmostIdle：当前网络连接数少于2后触发
* networkIdle：当前没有网络连接触发
* load：网页所有资源载入后触发，浏览器上加载转环停止旋转

一般情况下时间的触发顺序是：`DOMContentLoaded -> networkAlmostIdle -> networkIdle -> load`

实际上触发时间不一定，比如上面的baidu，之后networkAlmostIdle一定比networkIdle晚

#### 加载前后如何区分
关键点在于我们怎么判断页面加载完成

我们上看面的几个事件

应该说我第一次没有网络请求的时候就算获取完初始资源了，但是获取的资源如果再需要网络请求资源怎么办

如果load完就算没有资源了，但是如果load太快，还有动态ajax没有完成，完成后会改变网页怎么办

所以如果能按照一般的触发顺序`DOMContentLoaded -> networkAlmostIdle -> networkIdle -> load`就是好的，load就是结束，否则都很麻烦

看我上面提到的参考文章，说了3种

> 等待 load，同时设定等待超时时间，load 超时直接注入代码，同时等待 DOMContentLoaded事件

> DOMContentLoaded 事件触发，接着等待 networkAlmostIdle，同时设定等待超时时间，超时直接注入代码

> networkAlmostIdle 事件触发，接着等待 networkIdle 同时设定等待超时时间，超时直接注入代码

我实在没在pyppeteer种找到timeout还可以继续的接口，就改成了这样

```
await page.goto('https://www.baidu.com',
                 waitUntil=["networkidle0", "load", "domcontentloaded"],
                 timeout=10000)
```

不管三七二十一，上面的条件全用上，再加一个timeout的时间就可以了，真的，千万不要纠结

页面加载前：页面创建之后，用户代码执行之前的时间都是页面加载前

页面加载完成：timeout前，且load，domcontentloaded和networkidle都完成

页面加载后：页面加载完成后，开始用户代码执行
 
### 0x02 动态爬虫基础 
#### 先来体验一下
从这里开始，我们不用pychrome，改用pyppeteer，这一节我们体验一下puppeteer，为下一篇的细节进行准备

我们先来看一下pyppeteer爬取百度URL的简单例子

```
import asyncio
from pyppeteer.errors import TimeoutError
import pyppeteer


async def main():
    browser = await pyppeteer.connect({
        'browserWSEndpoint': 'ws://127.0.0.1:9222/devtools/browser/30261dd5-e97c-47d1-b3e1-0195bdff536c',
        'ignoreHTTPSErrors': True
    })
    page = await browser.newPage()
    try:
        await page.goto('https://www.baidu.com',
                        waitUntil=["networkidle0", "load", "domcontentloaded"],
                        timeout=10000)
        urls = await page.evaluate('''() => {
            var urls = new Array();
            var atags = document.getElementsByTagName("a");
            for (var i = 0; i < atags.length; i++) {
                if (atags[i].getAttribute("href")) {
                    urls[i] = atags[i].getAttribute("href")
                }
            }
            return urls;
        }
        ''')
        for url in urls:
            print(url)
    except TimeoutError as e:
        print('timeout')


asyncio.get_event_loop().run_until_complete(main())
```

上面`browserWSEndpoint`函数就是我上面写CDP运行的时候的输出，有了这个才会和CDP连接，这里要注意一下

这里我们看到`page.evaluate`注入执行了一些js代码

上面这段代码的输出为

```
/
javascript:;
javascript:;
javascript:;
javascript:;
/
javascript:;
https://passport.baidu.com/v2/?login&tpl=mn&u=http%3A%2F%2Fwww.baidu.com%2F
https://voice.baidu.com/act/newpneumonia/newpneumonia/?from=osari_pc_1
http://news.baidu.com
https://www.hao123.com
http://map.baidu.com
http://v.baidu.com
http://tieba.baidu.com
http://xueshu.baidu.com
https://passport.baidu.com/v2/?login&tpl=mn&u=http%3A%2F%2Fwww.baidu.com%2F
http://www.baidu.com/gaoji/preferences.html
http://www.baidu.com/more/
//www.baidu.com/s?rtt=1&bsst=1&cl=2&tn=news&word=
http://tieba.baidu.com/f?kw=&fr=wwwt
http://zhidao.baidu.com/q?ct=17&pn=0&tn=ikaslist&rn=10&word=&fr=wwwt
http://music.taihe.com/search?fr=ps&ie=utf-8&key=
http://image.baidu.com/search/index?tn=baiduimage&ps=1&ct=201326592&lm=-1&cl=2&nc=1&ie=utf-8&word=
http://v.baidu.com/v?ct=301989888&rn=20&pn=0&db=0&s=25&ie=utf-8&word=
http://map.baidu.com/m?word=&fr=ps01000
http://wenku.baidu.com/search?word=&lm=0&od=0&ie=utf-8
//www.baidu.com/more/
//www.baidu.com/cache/sethelp/help.html
http://home.baidu.com
http://ir.baidu.com
http://e.baidu.com/?refer=888
http://www.baidu.com/duty/
http://jianyi.baidu.com/
http://www.beian.gov.cn/portal/registerSystemInfo?recordcode=11000002000001
```

可以自己试试看和requests爬取链接有哪些不同

#### 页面加载前的js注入
更新，很遗憾，经过一段时间pyppeteer没有维护，以下的例子可能已经失效了

测试pyppeteer的`page.evaluateOnNewDocument`函数始终没有起作用，同样没有起作用还有`page.addScriptTag`函数

这两个函数我理解API的意思就是用来在页面加载前进行注入代码的，现在实际上不管我怎么测试都没有起效，不能hook js

```
import asyncio
from pyppeteer import launch


launch_options = {
    # "slowMo": 300,
    "headless": False,
    "devtools": True,
    "ignoreHTTPSErrors": True,
    "args": [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-gpu",
        "--disable-xss-auditor",
        "--no-sandbox",
    ]}


async def dialog_inject(dialog):
    print('[*] dialog type ' + dialog.type)
    print('[*] dialog message ' + dialog.message)
    print('[*] dialog defaultValue ' + dialog.defaultValue)
    # await dialog.accept()


async def request_inject(request):
    if request.resourceType in ['image', 'media', 'eventsource', 'websocket']:
        await request.abort()
    else:
        await request.continue_()


async def main():

    browser = await launch(launch_options)
    page = await browser.newPage()
    await page.goto('http://localhost:8333/test.html', waitUntil=["networkidle0", "load", "domcontentloaded"])
    await page.evaluateOnNewDocument("""
    window.alert = function(s){
        console.log("Hooked!");
    };
    """)
    await page.waitFor(300000)

asyncio.get_event_loop().run_until_complete(main())
```

以前这样就可以hook住alert函数，现在已经不能hook了

只要知道页面加载前通过`page.evaluateOnNewDocument`就可以注入js，hook函数，现在容易出问题，可以注入js，但是不能hook

#### 页面加载后的js注入
```
import asyncio
from pyppeteer import launch


launch_options = {
    # "slowMo": 300,
    "headless": False,
    "devtools": True,
    "ignoreHTTPSErrors": True,
    "args": [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-gpu",
        "--disable-xss-auditor",
        "--no-sandbox",
    ]}


async def dialog_inject(dialog):
    print('[*] dialog type ' + dialog.type)
    print('[*] dialog message ' + dialog.message)
    print('[*] dialog defaultValue ' + dialog.defaultValue)
    # await dialog.accept()


async def request_inject(request):
    if request.resourceType in ['image', 'media', 'eventsource', 'websocket']:
        await request.abort()
    else:
        await request.continue_()


async def main():

    browser = await launch(launch_options)
    page = await browser.newPage()
    await page.goto('http://localhost:8333/test.html', waitUntil=["networkidle0", "load", "domcontentloaded"])
    await page.evaluate("""
    window.alert =function(s){
        console.log("Hooked!");
    };
        alert("123");
    """)
    await page.waitFor(300000)

asyncio.get_event_loop().run_until_complete(main())
```

这个就好理解了，打开网页后，注入js，这个可以hook成功，console会输出`Hooked!`

知道了怎么hook，怎么注入js，我们就结束了这一篇，开始下一篇讲细节