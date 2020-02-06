---
title: 启发式爬虫
description: 根据猪猪侠在先知白帽大会的PPT写的爬虫
categories:
 - 安全开发 
tags:
 - 安全开发
---


### 基础知识
启发式爬虫：基于历史经验和已知场景，构造并实现规则的爬虫

主要的点：

* hook所有的网络请求
* 静态页面链接分析，如href、frame等等
* javascript动态解析，触发click等操作
* 自动分析表单幷提交

#### BOM(Browser Object Model)
#### DOM(Document Object Model)
#### CDP(Chrome DevTools Protocol)
#### puppeteer | pyppeteer
为了方便，以下pyppeteer即是指代puppeteer

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

