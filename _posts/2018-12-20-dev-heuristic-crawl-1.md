---
title: 扫描器里的动态爬虫的一些经验
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

不管三七二十一，上面的条件全用上，在加一个timeout的时间就可以了，真的，千万不要纠结

页面加载前：页面创建之后，用户代码执行之前的时间都是页面加载前

页面加载完成：timeout前，且load，domcontentloaded和networkidle都完成

页面加载后：页面加载完成后，开始用户代码执行
 
### 0x02 动态爬虫基础 
#### 先来体验一下
从这里开始，我们不用pychrome，改用pyppeteer

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

#### 页面加载后的js注入

### 基础知识
启发式爬虫：基于历史经验和已知场景，构造并实现规则的爬虫

主要的点：

* hook所有的网络请求
* 静态页面链接分析，如href、frame等等
* javascript动态解析，触发click等操作
* 自动分析表单幷提交

#### JS hook
遇到的问题无非是hook住BOM的函数和变量，然后获取数据

```
def echo_console(msg):
    print("console text " + msg.text)
    print("console type " + msg.type)
    print("console args " + str(msg.args))
    for arg in msg.args:
        print("console arg " + str(arg))
        
await page.evaluateOnNewDocument("""
function () {
    window.__injected=43;
    window.__injectedError=new Error('hi');
    window.__injectedFunc=function() {
        console.log("abcd");
    };
}
""")

page.on("console", lambda msg: echo_console(msg))
```

有`page.evaluate*`和`page.addScriptTag`等方法可以注入JS，个人试用过后选择`page.evaluateOnNewDocument`方法，这个方法的作用是：

```
添加一个方法，在以下某个场景被调用：
页面导航完成后
页面的iframe加载或导航完成。这种场景，指定的函数被调用的上下文是新加载的iframe。
指定的函数在所属的页面被创建并且所属页面的任意 script 执行之前被调用。常用于修改页面js环境，比如给 Math.random 设定种子
```

可以在其他script执行前执行，适合hook，其他函数调用时要注意顺序，比如`addScriptTag`在`page.goto`后加载有效，不然会被覆盖

此时如上面代码，可以hook住BOM的变量和函数，同时可以通过`console.log`来获取BOM等能获取到的数据

### 页面加载
```
await page.goto("https://www.seebug.org", waitUntil=["networkidle0", "load", "domcontentloaded"])
```

pyppeteer中对`page.goto`的自带了`waitUntil`参数，判断页面加载完成的标志

判断的状态有`load`, `domcontentloaded`, `networkidle2`, `networkidle0`，详细解释可以看文档

```
async def empty():
    print("load")
    
page.on("load", await empty)
await page.waitForFunction("""() => {
    return document.readyState === "complete";
}""")
```

也可以使用上面的方式对hook住`load`等方法后再执行代码，或者`waitFor*`类函数判断`document.readyState`的状态等方式判断页面是否加载完成，在我尝试下效果是一样的

注意访问`http://www.seebug.org`时会重定向到`https://www.seebug.org`，此时页面未加载完全但是前面提到到加载完全的判断成立，有时会因为这种问题页面未加载完全就停止了，所以初始页面的域名、协议等信息要准确，或者对重定向之后爬取程序进行完善

### 页面控制以及超时阻塞
#### 页面跳转
解决以下问题

```
window.open()
window.location = "/123"
window.location = "/456"
```

猪猪侠的PPT里对页面跳转采用编写Chrome插件的方式，插件编写可以通过[MDN浏览器扩展模块](https://developer.mozilla.org/zh-CN/docs/Mozilla/Add-ons/WebExtensions)和[360 Chrome Extension 文档](http://open.chrome.360.cn/extension_dev/overview.html)中的例子进行学习，pyppeteer中加载插件的方式为

```
from pyppeteer import launch
from pathlib import Path
import time
extensionPath = Path(__file__).parent / 'static' / 'extensions'

launch_options = {
    "args": [
        "--disable-extensions-except={}".format(extensionPath),
        "--load-extensions={}".format(extensionPath),
    ] }

browser = await launch(launch_options)
```

实际上我把学习写插件的参考文档里的插件直接作为加载的插件也没有生效，因为插件开发我不可控，所以没有使用这个方法，可以持续关注这个[git issue](https://github.com/GoogleChrome/puppeteer/issues/823)，可能以后会更新

使用hook的方式兴许比较好

pypeteer里的`request.isNavigationRequest`和`request.redirecChain`可以有效去掉301，302等跳转，视情况看去不去掉跳转

```
async def stop_redirect(request):
    if request.isNavigationRequest and len(request.redirectChain):
        print("request await")
            await request.continue_({"url": "javascript:void(0)"})
    else:
            await request.continue_() 

await page.setRequest.Interception(True)
page.on("request", lambda request: asyncio.ensure_future(redirect(request)))
page.goto(...)
```

#### 弹框(alert/confirm/prompt/beforeunload)
```
page.on("dialog", lambda dialog: await dialog.accept())
```

#### 新frame打开
```
page.on("framenavigated", lambda frame: print(frame.url))
```

#### window的open/close
JS Hook
```
window.close = function() {}
window.open = function(url) { console.log(url); };
```

#### window和setTimeout/setInterval
JS Hook
```
window.__originSetTimeout = window.setTimeout;
window.setTimeout = function() {
    arguments[1] = 0;
    return window.__originalSetTimeout.apply(this, arguments);
};
window.__originSetInterval = window.setInterval;
window.setInterval = function() {
    arguments[1] = 0;
    return window.__originalSetInterval.apply(this, arguments);
}
```

### 事件触发
#### 获取需要触发的事件
常用事件(onclick/ondblclick/onkeyup/onkeydown/onmouseup/onmousedown/onchange/onblur/onfocus/onscroll)

* button(click/dblclick/keyup/keydown/mouseup/mousedown)
* select(change/click/keyup/keydown/mouseup/mousedown)
* input(change/click/blur/focus/keyup/keydown/mouseup/mousedown)
* a(click/dblclick/keyup/keydown/mouseup/mousedown)
* textarea(chagne/click/blur/focus/keyup/keydown/mouseup/mousedown)
* span(click/mouseup/mousedown)
* td(click/mouseup/mousedown)
* tr(click/mouseup/mousedown)
* div(click/mouseup/mousedown/scroll)

用`document.all`和`document.createTreeWalker`遍历节点事件

```
nodes = document.all;
for (j = 0; j < nodes.length; j++) {
    attrs = nodes[j].attributes;
    for (attrs[k].nodeName.startsWith('on')) {
        console.log(attrs[k].nodeName, attrs[k].nodeValue);
    }
}

var treeWalker = document.createTreeWalker(
    document.body, 
    NodeFilter.SHOW_ELEMENT,
    { acceptNode: function(node) { return NodeFilter.FILTER_ACCEPT; }},
);
while (treeWalker.nextNode()) {
    var element = treeWalker.currentNode;
    for (k = 0; k < element.attributes.length; k++) {
        attr = element.attributes[k]
        if (attr.nodeName.startsWith('on')) {
            console.log(attr.nodeName, attr.nodeValue);
        }
    }
}
```

以上两个方式对输出皆为
```
onclick alert(document.getElementById('jsCode').innerHTML);return false;
onclick alert(document.getElementById('formCode').innerHTML);return false;
onclick alert(document.getElementById('clickCode').innerHTML);return false;
onclick abc.innerHTML ='<a href=click_link.php'+'?id=2>click_link.php?id=2</a>'
onclick alert(document.getElementById('ajaxCode').innerHTML);return false;
onclick alert(document.getElementById('ifCode').innerHTML);return false;
```

推荐用第二种方式，因为页面变动后从头遍历一遍不够好，使用`document.createTreeWalker`可以指定起点node，封装一下方便增量的问题

#### 事件触发
找到node和事件类型后要将其触发，有`dispatchEvent`和`eval`方式

```
// <button id='elem' onclick="alert('click!');">Click</button>
let event = new Event("click");
elem.dispatchEvent(event);

for (var i = 0; i < elem.attributes.length; i++) {
    var element = elem.attributes[i]
    if (element.nodeName.startsWith('on')) {
        eval(element.nodeValue);
    }
}
```

模拟鼠标移动
```
var evt = document.createEvent("MouseEvents");
evt.initMoouseEvent("click", true, true, window, 0, 0, 0, 0, 0, false, false, flase, false, 0, null);
```


#### 监听需要触发的事件
触发事件后要获取变化

使用[`addEventListener`](https://developer.mozilla.org/zh-CN/docs/Web/API/EventTarget/addEventListener)和[MutationObserver](https://wangdoc.com/javascript/dom/mutationobserver.html)的方式监听需要触发的事件

```
// <button id='y'>test</button>
y.addEventListener('click', function (element) {
    console.log(element);
}, false);
```

点击事件发生后输出为

```
MouseEvent {isTrusted: true, screenX: 1148, screenY: 463, clientX: 212, clientY: 330, …}
```

```
var observer = new WebKitMutationObserver(function(mutations) {
    console.log("eventLoop nodesMutated:', mutations.length);
    mutations.forEach(function(mutation) {
        if (mutation.type === 'childList') {
            for (let i = 0; i < mutation.addNodes.length; i++) {
                let addedNode = mutation.addedNodes[i];
                console.log('Node added:', addedNode.nodeType, mutation.addedNodes[i]);
            }
        } else if (mutation.type === 'attributes') {
            let element = mutation.target;
            var element_val = element.getAttribute(mutation.attributeName)
            console.log(mutation.attributeName, '->', element_val)
        }
    });
});
```

点击事件发生后输出为

```
eventLoop nodesMutated: 1
Node added: 1 <a href=​"click_link.php?id=2">​click_link.php?id=2​</a>​
```

建议使用`MutationObserver`方法，异步且不用一个一个node绑定监听


### 获取请求
#### 获取普通请求
```
#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
resp = requests.get("https://www.seebug.org")
soup = BeautifulSoup(resp.content, "lxml")
resources = {
    "anchor": (soup.find_all('a'), "href"),
    "iframe": (soup.find_all("iframe"), "src"),
    "frame": (soup.find_all("frame"), "src"),
    "img": (soup.find_all("img"), "href"),
    "link": (soup.find_all("link"), "href"),
    "script": (soup.find_all("script"), "src"),
    "form": (soup.find_all("form"), "action"),
}
print(resources)
```

```
#! /usr/bin/env python3

import asyncio
from pyppeteer import launch
async def main():
    browser = await launch()
    page = await browser.newPage()
    await page.goto("http://www.seebug.org")
    await page.waitFor("body" > div.footer-up")
    urls = await page.evalute("""() => {
        var urls = new Array();
        var atags = document.getElementsByTagName('a');
        for (let i = 0; i < atags.length; i++) {
            if (atags[i].getAttribute("href")) {
                urls[i] = atags[i].getAttribute("href")
            }
        }
        return urls;
    }""")
```

#### 获取Form表单请求
```
for (let i = 0; i < document.forms.length; i++) {
    form = document.forms[i];
    console.log(form.method, form.action)
    for (var j = 0; j < form.length; i++) {
        input = form[j];
        console.log(input.nodeName, input.type, input.name);
    }
}
```

#### 获取AJAX请求
hook住console然后启用请求拦截过滤处理都方式比较好
```
await page.setRequestInterception(true);
page.on("request", request => {
    console.log(request.url());
    request.continue();
});
```

也可以劫持原⽣类 XMLHttpRequest
```
XMLHttpRequest.prototype.__originalOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
    // hook code
    return this.__originalOpen(method, url, async, user, password);
}
XMLHttpRequest.prototype.__originalSend = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.send = function(data) {
    // hook code
    return this.__originalSend(data);
}
```

### 其他
#### 保持Session独立
```
var context = await browser.createIncognitoBrowserContext();
var page = await context.newPage();
await page.goto("http://mail.aliyun.com");
var cookies = await page.cookies();
console.log(cookies);
await page.close();
await context.close();
```

#### 去重
ast分析将一些特殊格式转化掉

```
import ast
def var(x):
    try:
        if not isinstance(x, str):
            x = str(x)
        return ast.literal_eval(x)
    except:
        try:
            x = x.replace('\'', "\\'")
            return ast.literal_eval("'{0}'".format(x))
        except:
            return "xz"

In [1]: type(var("123"))
out[1]: int

In [2]: type(var("news"))
Out[2]: str
```


